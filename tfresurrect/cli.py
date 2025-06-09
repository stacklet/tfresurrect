import boto3
import click
from collections import defaultdict
from graphlib import TopologicalSorter
from c7n.resources import load_resources
from c7n.resources.aws import Arn, AWS
from c7n.policy import Policy
from c7n.config import Config
from c7n.utils import filter_empty
from c7n.manager import resources as c7n_resources
from c7n.query import ChildResourceManager, TypeInfo
import jmespath
import json
import logging
import hcl2
import operator
import pprint
from pathlib import Path
import re
import subprocess


__author__ = "Kapil Thangavelu <kapil@stacklet.io>"


log = logging.getLogger("tfresurrect")


class AmbigiousError(ValueError):
    pass


@c7n_resources.register("user-pool-client")
class CognitoUserPoolClient(ChildResourceManager):
    class resource_type(TypeInfo):
        service = "cognito-idp"
        parent_spec = ("user-pool", "UserPoolId", None)
        enum_spec = ("list_user_pool_clients", "UserPoolClients", {"MaxResults": 60})
        # detail_spec = (
        #     'describe_user_pool_client', 'ClientId', 'UserPoolId', )
        id = "ClientId"
        name = "ClientName"
        arn_type = "userpoolclient"
        cfn_type = "AWS::Cognito::UserPoolClient"


def get_env_resources(group):
    # https://docs.aws.amazon.com/ARG/latest/userguide/supported-resources.html
    # lots of notables, iam roles, lambda layers, ecs services, etc
    client = boto3.client("resource-groups")
    pager = client.get_paginator("list_group_resources")
    group_resources = (
        pager.paginate(Group=group).build_full_result().get("ResourceIdentifiers")
    )
    env_resources = {}
    for r in group_resources:
        env_resources.setdefault(r["ResourceType"].lower(), []).append(r["ResourceArn"])
    return env_resources


def get_state_resources(tf_dir):
    output = subprocess.check_output(["terraform", "show", "-json"], cwd=tf_dir)
    state = json.loads(output)
    state_resources = {}

    resources = jmespath.search("values.root_module.resources", state) or ()
    if not resources:
        log.info("empty state")

    for r in resources:
        state_resources[r["address"]] = {
            "id": r["values"]["id"],
            "arn": r["values"].get("arn"),
        }
    return state_resources


def get_hcl_resources(tf_dir):
    resources = {}
    variables = {}

    for tf in Path(str(tf_dir)).rglob("**/*.tf"):
        tf_data = hcl2.loads(tf.read_text())
        for r in tf_data.get("resource", ()):
            rtype = list(r.keys()).pop()
            for rname in r[rtype].keys():
                rdef = r[rtype][rname]
                resources[f"{rtype}.{rname}"] = {"def": rdef}

        for tvar in tf_data.get("variable", ()):
            for k, v in tvar.items():
                if v.get("default") is not None:
                    variables[k] = v["default"][0]

    for tfjson in Path(str(tf_dir)).rglob("**/*.tf.json"):
        tf_data = json.loads(tfjson.read_text())
        for rtype, rset in tf_data.get("resource").items():
            for rname, rdef in rset.items():
                resources[f"{rtype}.{rname}"] = {"def": arrayify(rdef)}
    return resources, variables


def arrayify(n):
    for k, v in list(n.items()):
        if isinstance(v, dict):
            arrayify(v)
        elif isinstance(v, list):
            continue
        elif isinstance(v, (int, str, bool)):
            n[k] = [v]
    return n


def get_graph(tresources):
    graph = defaultdict(list)
    for t in tresources:
        tdef = tresources[t]["def"]
        for r in get_refs(tdef):
            if not r.startswith("aws"):
                continue
            graph[t].append(r)
        else:
            if t.startswith("aws"):
                graph[t] = []
    return graph


def build_resource_id(name, tdef):
    if "count" in tdef:
        return f"{name}[0]"
    if "for_each" in tdef:
        log.info(f"Unable to handle for_each {name} - {tdef}")
    return name


def sorted_graph(tresources):
    """sort the dependencies by the resource graph dependency order

    dependencies determined by references between resources.
    """
    ts = TopologicalSorter(get_graph(tresources))
    return ts.static_order()


TF_REF_REGEX = re.compile("\$\{(?P<ref>.*?)\}")  # noqa


def get_refs(tdef):
    refs = []
    for k, v in tdef.items():
        for e in v:
            if not isinstance(e, str):
                continue
            elif "${aws_" in e:
                for r in TF_REF_REGEX.search(e).groups("ref"):
                    if "aws" in r:
                        refs.append(r.rsplit(".", 1)[0])
            elif "aws_" in e:
                refs.append(e)
    return refs


class VariableResolver:
    # limited variable resolution and substution to get at string for identity fields
    # at the moment we're not bothering with expressions evaluation on locals
    # we expect the user to provide us an explicit locals mapping.

    def __init__(self, tf_vars, tf_locals):
        self.tf_vars = tf_vars
        self.tf_locals = tf_locals

    def resolve_identity(self, ident):
        ident = self._resolve_locals(ident)
        ident = self._resolve_variables(ident)
        return ident

    resolve = resolve_identity

    @staticmethod
    def get_regex(name, var=False, local=False):
        assert var or local
        if var:
            return re.compile("((?:\$\{)?var[.]" + name + "(?:\})?)")  # noqa
        if local:
            return re.compile("((?:\$\{)?local[.]" + name + "(?:\})?)")  # noqa

    def _resolve_variables(self, ident):
        for k in sorted(self.tf_vars.keys(), key=lambda x: len(x), reverse=True):
            if f"var.{k}" not in ident:
                continue
            regex = self.get_regex(k, var=True)
            v = self.tf_vars[k]
            if isinstance(v, list):
                v = v[0]
            if not isinstance(v, str):
                v = json.dumps(v)
            ident = regex.sub(v, ident)
        return ident

    def _resolve_locals(self, ident):
        for k in sorted(self.tf_locals.keys(), key=lambda x: len(x), reverse=True):
            if f"local.{k}" not in ident:
                continue
            v = self.tf_locals[k]
            if isinstance(v, list):
                v = v[0]
            regex = self.get_regex(k, local=True)
            ident = regex.sub(v, ident)
        return ident


class ResourceResolver:
    """Resolve an a terraform hcl identifier to an importable resource id"""

    hcl_cfn_type_map = {
        "aws::security::group": "aws::ec2::securitygroup",
        "aws::db::instance": "aws::rds::dbinstance",
        "aws::cloudwatch::eventrule": "aws::events::rule",
        "aws::cloudwatch::loggroup": "aws::logs::loggroup",
        "aws::lb::targetgroup": "AWS::ElasticLoadBalancingV2::TargetGroup".lower(),
        "aws::elasticache::subnet_group": "aws::elasticache::subnetgroup",
        "aws::sfn::statemachine": "AWS::StepFunctions::StateMachine".lower(),
        "aws::api::gatewayrestapi": "aws::apigateway::restapi",
        "aws::acm::certificate": "AWS::CertificateManager::Certificate".lower(),
    }
    hcl_type = {"aws_lb": "AWS::ElasticLoadBalancingV2::LoadBalancer".lower()}

    arn_imports = set()

    def __init__(self, var_resolver, eresources, tresources, tstate, ident_map):
        #
        # eresources - environment resources from cloud provider <cfn_type>: [arns]
        #   - note this will be missing resources that resource groups don't support.
        #   - for this we will directly use cloud custodian to fetch the resources.
        # tresources - hcl resources definitions
        # tstate - terraform state resources
        # ident_map - manually mapped entries, escape hatch.
        self.var_resolver = var_resolver
        self.eresources = eresources
        self.tresources = tresources
        self.tstate = tstate
        self.ident_map = ident_map
        self._resolve_cache = {}
        self._resource_cache = {}
        self._clients = {}

        client = boto3.client("sts")
        # we try to not to use this but in some cases we're generating arns.
        self.account_id = client.get_caller_identity().get("Account")
        self.region = client.meta.region_name

        # dynamic lookup
        self.rmanager = Policy(
            {"name": "resolver", "resource": "aws.ec2"},
            Config.empty(region=self.region, account_id=self.account_id),
        ).resource_manager

    def get_cfn_type(self, logical_id):
        tf_type = logical_id.split(".", 1)[0]
        if tf_type in self.hcl_type:
            return self.hcl_type[tf_type]

        provider, rservice, rtype = tf_type.split("_", 2)
        rtype = rtype.replace("_", "")
        etype = f"{provider}::{rservice}::{rtype}"
        return self.hcl_cfn_type_map.get(etype, etype)

    def get_identity(self, rdef):
        # default get identity from definition
        physical_id = None
        if "name" in rdef:
            physical_id = rdef["name"]
        elif "identifier" in rdef:
            physical_id = rdef["id"]
        return physical_id and physical_id[0] or None

    def resolve(self, logical_id, rdef):
        """
        params:
          logical_id == aws_sqs_queue.trail_event_queue
          hcl_ident = name/id attribute with block, post variable resolution
        """
        named_handler = "resolve_%s" % logical_id.split(".", 1)[0]
        resolver = getattr(self, named_handler, self.resolve_default)
        result = resolver(logical_id, rdef)
        if result is None:
            print(f"resolve {logical_id} failed")
        else:
            self._resolve_cache[logical_id] = result
        return result

    def resolve_default(self, logical_id, rdef, arn=False, multi=False):
        # only works for things that are supported by aws resource group tagging.
        # - iam roles aren't returned by resource group tagging :(
        # - elasticache cache subnet groups :(
        # - ecs-services aren't returned
        #
        # review full sadness on partial support
        # https://docs.aws.amazon.com/ARG/latest/userguide/supported-resources.html
        #

        ident = self.get_identity(rdef)
        assert ident, "no identity for resource"
        hcl_ident = self.var_resolver.resolve_identity(ident)
        cfn_type = self.get_cfn_type(logical_id)

        if cfn_type not in self.eresources:
            log.info("no type candidates for %s %s", cfn_type, logical_id)
            return

        candidates = self.eresources[cfn_type]
        found = False

        if multi:
            return candidates

        for c in candidates:
            if hcl_ident in c:
                found = c
                break

        if not found:
            return found
        if arn is True:
            return found
        parsed_arn = Arn.parse(found)
        if (parsed_arn.service, parsed_arn.resource_type) not in self.arn_imports:
            return parsed_arn.resource
        return found

    def _resolve_ref(self, logical_id):
        if logical_id in self._resolve_cache:
            return self._resolve_cache[logical_id]
        elif logical_id in self.tstate:
            return self.tstate[logical_id]["id"]
        elif logical_id in self.ident_map:
            return self.ident_map[logical_id]
        elif logical_id in self.tresources:
            # hack to get around bad dep order due to issue in get refs with multiple vars
            self.resolve(logical_id, self.tresources[logical_id]["def"])
            return self._resolve_ref(logical_id)
        else:
            raise ValueError("unknown logical id %s" % logical_id)

    def _resolve_resources(self, cfn_type, rids=None, env=True):
        if cfn_type in self._resource_cache:
            return self._resource_cache[cfn_type]
        found = None
        for rtype, v in AWS.resources.items():
            if v.resource_type.cfn_type is None:
                continue
            if v.resource_type.cfn_type.lower() == cfn_type:
                found = rtype
                break
        if found is None:
            raise ValueError(
                "could not find matching resource for cfn_type:%s" % cfn_type
            )
        kmanager = self.rmanager.get_resource_manager(rtype)
        cache = True
        if rids:
            cache = False
        if not rids and env is True:
            candidates = self.eresources.get(cfn_type, ())
            rids = [Arn.parse(c).resource for c in candidates]
        if rids:
            resources = kmanager.get_resources(rids)
        else:
            resources = kmanager.resources()
        if cache:
            self._resource_cache[cfn_type] = resources
        return resources

    def _value(self, rdef, key):
        v = rdef.get(key)
        if isinstance(v, list):
            return v[0]

    def _client(self, service):
        if service in self._clients:
            return self._clients[service]
        self._clients[service] = client = boto3.client(service)
        return client

    def resolve_aws_cognito_user_pool(self, logical_id, rdef):
        name = self.var_resolver.resolve(rdef["name"][0])
        resources = self._resolve_resources(self.get_cfn_type(logical_id), env=False)
        for r in resources:
            if r["Name"] == name:
                return r["Id"]

    def resolve_aws_cognito_user_pool_client(self, logical_id, rdef):
        user_pool = self.var_resolver.resolve(rdef["user_pool_id"][0])
        resources = self._resolve_resources(self.get_cfn_type(logical_id), env=False)
        for r in resources:
            if r["UserPoolId"] == user_pool:
                return f"{user_pool}/{r['ClientId']}"

    def resolve_aws_acm_certificate(self, logical_id, rdef):
        domain_name = self.var_resolver.resolve(rdef["domain_name"][0])
        resources = self._resolve_resources(self.get_cfn_type(logical_id), env=False)
        for r in resources:
            if r["DomainName"] == domain_name:
                return r["CertificateArn"]

    def resolve_aws_route53_record(self, logical_id, rdef):
        if "for_each" in rdef:
            # Skip trying to resolve for_each loop'd records.
            return None
        zone_id = self.var_resolver.resolve(rdef["zone_id"][0])
        domain_name = self.var_resolver.resolve(rdef["name"][0])
        if "${" in domain_name:
            log.info(
                f"Skipping due to unresolved variable {logical_id}, {domain_name}, {rdef}"
            )
            return None
        return f"{zone_id}_{domain_name}_{rdef['type'][0]}"

    def resolve_aws_cognito_identity_provider(self, logical_id, rdef):
        # ugh... too much indirection can.
        # look for a user pool in this same stack
        keys = [
            k
            for k in self._resolve_cache.keys()
            if k.startswith("aws_cognito_user_pool.")
        ]
        name = self.var_resolver.resolve(rdef["provider_name"][0])
        if keys:
            pool_id = self._resolve_ref(keys[0])
            return "%s:%s" % (pool_id, name)

    def resolve_aws_cognito_user_pool_domain(self, logical_id, rdef):
        return self.var_resolver.resolve(rdef["domain"][0])

    def resolve_aws_s3_bucket_public_access_block(self, logical_id, rdef):
        return self.var_resolver.resolve(rdef["bucket"][0])

    def resolve_aws_s3_bucket_object(self, logical_id, rdef):
        return

    def resolve_aws_s3_bucket(self, logical_id, rdef):
        return self.var_resolver.resolve(rdef["bucket"][0])

    def resolve_aws_elasticsearch_domain(self, logical_id, rdef):
        return self.var_resolver.resolve(rdef["domain_name"][0])

    def resolve_aws_cloudwatch_event_bus(self, logical_id, rdef):
        return self.var_resolver.resolve(rdef["name"][0])

    def resolve_aws_lambda_layer_version(self, logical_id, rdef):
        resources = self._resolve_resources(self.get_cfn_type(logical_id))
        name = self.var_resolver.resolve(rdef["layer_name"][0])
        candidates = []
        for r in resources:
            if r["LayerName"] == name:
                candidates.append(r)
        candidates = sorted(
            candidates, key=operator.itemgetter("Version"), reverse=True
        )
        if candidates:
            return candidates[0]["LayerVersionArn"]

    def resolve_aws_elasticsearch_domain_policy(self, logical_id, rdef):
        # terraform doesn't support import on this afaics
        # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain_policy
        return

    def resolve_aws_acm_certificate_validation(self, logical_id, rdef):
        # terraform doesn't support import on this afaics
        # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/acm_certificate_validation
        return

    def resolve_aws_ecr_repository_policy(self, logical_id, rdef):
        return self._resolve_ref(get_refs({"repo": rdef["repository"]})[0])

    def resolve_aws_api_gateway_rest_api(self, logical_id, rdef):
        resources = self._resolve_resources(self.get_cfn_type(logical_id), env=False)
        name = self.var_resolver.resolve(rdef["name"][0])
        for r in resources:
            if r["name"] == name:
                return r["id"]

    def resolve_aws_api_gateway_domain_name(self, logical_id, rdef):
        return self.var_resolver.resolve(rdef["domain_name"][0])

    def resolve_aws_sns_topic(self, logical_id, rdef):
        name = self.var_resolver.resolve(rdef["name"][0])
        return "arn:aws:sns:{region}:{account_id}:{name}".format(
            region=self.region, account_id=self.account_id, name=name
        )

    def resolve_aws_sns_topic_subscription(self, logical_id, rdef):
        client = self._client("sns")
        topic = rdef["topic_arn"][0]

        if "chalice" in topic:
            tname = get_refs({"topic": [topic.rsplit(":", 1)[-1]]})[0]
        else:
            tname = get_refs({"topic": [topic]})[0]

        # ugly due to lack of chalice arn ref parsing
        try:
            t = self._resolve_ref(tname)
        except ValueError:
            self.resolve(tname, self.tresources[tname]["def"])
            t = self._resolve_ref(tname)
        return client.list_subscriptions_by_topic(TopicArn=t,).get("Subscriptions")[
            0
        ]["SubscriptionArn"]

    def resolve_aws_lb(self, logical_id, rdef):
        name = self.var_resolver.resolve(rdef["name"][0])
        resources = self._resolve_resources(self.get_cfn_type(logical_id), rids=(name,))
        if resources:
            return resources[0]["LoadBalancerArn"]

    def resolve_aws_lb_target_group(self, logical_id, rdef):
        name = self.var_resolver.resolve(rdef["name"][0])
        resources = self._resolve_resources(self.get_cfn_type(logical_id), env=False)
        for r in resources:
            if r["TargetGroupName"] == name:
                return r["TargetGroupArn"]

    def resolve_aws_lb_target_group_attachment(self, logical_id, rdef):
        # not supported
        # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_target_group_attachment
        return None

    def resolve_aws_api_gateway_deployment(self, logical_id, rdef):
        # not supported afaics
        return None

    def resolve_aws_lb_listener(self, logical_id, rdef):
        lb_arn = self._resolve_ref(get_refs({"balance": rdef["load_balancer_arn"]})[0])
        client = self._client("elbv2")
        listeners = client.describe_listeners(LoadBalancerArn=lb_arn).get(
            "Listeners", ()
        )
        port = int(rdef["port"][0])
        protocol = rdef["protocol"][0]
        found = None
        for l in listeners:  # noqa
            if l["Port"] != port:
                continue
            if l["Protocol"] != protocol:
                continue
            found = l
        return found and found["ListenerArn"] or found

    def resolve_aws_api_gateway_base_path_mapping(self, logical_id, rdef):
        domain = self.var_resolver.resolve(rdef["domain_name"][0])
        path = rdef.get("base_path", ("/",))[0]
        return f"{domain}{path}"

    def resolve_aws_lambda_event_source_mapping(self, logical_id, rdef):
        client = self._client("lambda")
        source = get_refs({"source": rdef["event_source_arn"]})[0]
        func = self._resolve_ref(get_refs({"func": rdef["function_name"]})[0])
        if source.startswith("aws_dynamodb_table"):
            resources = self._resolve_resources(
                "aws::dynamodb::table", rids=(self._resolve_ref(source),)
            )
            stream_arn = resources[0]["LatestStreamArn"]
            try:
                return client.list_event_source_mappings(
                    EventSourceArn=stream_arn, FunctionName=func
                ).get("EventSourceMappings")[0]["UUID"]
            except IndexError:
                return
        elif "sqs" in rdef["event_source_arn"][0]:
            sqs = get_refs({"source": [rdef["event_source_arn"][0].rsplit(":")[-1]]})
            queue_url = self._resolve_ref(sqs[0])
            name = queue_url.rsplit("/", 1)[-1]

            queue_arn = f"arn:aws:sqs:{self.region}:{self.account_id}:{name}"
            try:
                return client.list_event_source_mappings(
                    EventSourceArn=queue_arn, FunctionName=func
                ).get("EventSourceMappings")[0]["UUID"]
            except IndexError:
                return
        else:
            raise NotImplementedError("unsupport stream type %s" % source)

    def resolve_aws_lambda_permission(self, logical_id, rdef):
        # if its not a qualified statement then its automagic
        func = self._resolve_ref(get_refs({"func": rdef["function_name"]})[0])
        if "statement_id" in rdef:
            sid = self.var_resolver.resolve(rdef["statement_id"][0])
            return f"{func}/{sid}"
        client = self._client("lambda")
        data = json.loads(client.get_policy(FunctionName=func).get("Policy")) or {}
        for s in data.get("Statement", ()):
            if s["Action"] != rdef["action"][0]:
                continue
            if s["Principal"].get("Service") != rdef["principal"][0]:
                continue
            sid = s["Sid"]
        return f"{func}/{sid}"

    def resolve_aws_sfn_state_machine(self, logical_id, rdef):
        name = self.var_resolver.resolve(rdef["name"][0])
        return "arn:aws:states:{region}:{account_id}:stateMachine:{name}".format(
            region=self.region, account_id=self.account_id, name=name
        )

    def resolve_aws_lambda_function(self, logical_id, rdef):
        return self.var_resolver.resolve(rdef["function_name"][0])

    def resolve_aws_iam_policy(self, logical_id, rdef):
        return "arn:aws:iam::{account_id}:policy/{name}".format(
            account_id=self.account_id, name=self.var_resolver.resolve(rdef["name"][0])
        )

    def resolve_aws_iam_role_policy_attachment(self, logical_id, rdef):
        role_refs = get_refs({"role": rdef["role"]})
        if role_refs:
            role = self._resolve_ref(role_refs[0])
        else:
            role = rdef["role"][0]
        policy_refs = get_refs({"policy_arn": rdef["policy_arn"]})
        if policy_refs:
            policy = self._resolve_ref(policy_refs[0])
        else:
            policy = rdef["policy_arn"][0]
        return f"{role}/{policy}"

    def resolve_aws_ecs_task_definition(self, logical_id, rdef):
        tdefs = self._resolve_resources(self.get_cfn_type(logical_id))
        family = self.var_resolver.resolve(rdef["family"][0])
        for t in tdefs:
            if t["family"] == family:
                return t["taskDefinitionArn"]

    def resolve_aws_security_group_rule(self, logical_id, rdef):
        ref_sg_id = get_refs({"sg_id": rdef["security_group_id"]})[0]
        sg_id = self._resolve_ref(ref_sg_id)
        direction = rdef["type"][0]
        protocol = rdef["protocol"][0]

        source_group = get_refs({"sg": rdef.get("source_security_group_id", ())})
        if source_group:
            source_group = self._resolve_ref(source_group[0])

        blocks = []
        for b in rdef.get("cidr_blocks", ()):
            if isinstance(b, str):
                b = [b]
            for e in b:
                if "var." in e:
                    e = json.loads(self.var_resolver.resolve(e))
                if isinstance(e, list):
                    blocks.extend(e)
                else:
                    blocks.append(e)
        if blocks:
            cidr = "_".join(blocks)
        if source_group:
            cidr = source_group
        from_port = rdef["from_port"][0]
        to_port = rdef["to_port"][0]
        return f"{sg_id}_{direction}_{protocol}_{from_port}_{to_port}_{cidr}"

    def resolve_aws_iam_role_policy(self, logical_id, rdef):
        role = self._resolve_ref(get_refs({"role": rdef["role"]})[0])
        name = self.var_resolver.resolve(rdef["name"][0])
        return f"{role}:{name}"

    def resolve_aws_kms_alias(self, logical_id, rdef):
        return self.var_resolver.resolve(rdef["name"][0])

    def resolve_aws_elasticache_replication_group(self, logical_id, rdef):
        return self.var_resolver.resolve(rdef["replication_group_id"][0])

    def resolve_aws_secretsmanager_secret_version(self, logical_id, rdef):
        secret_ref = get_refs({"secret": rdef["secret_id"]})
        if not secret_ref:
            return None
        secret_id = self._resolve_ref(secret_ref[0])
        name = secret_id.rsplit("-", 1)[0]
        secrets = self._resolve_resources("aws::secretsmanager::secret", rids=(name,))
        for s in secrets:
            if s["ARN"].endswith(secret_id):
                version_id = list(s["VersionIdsToStages"]).pop(0)
                return "%s|%s" % (s["ARN"], version_id)

    def resolve_aws_cloudwatch_event_rule(self, logical_id, rdef):
        if "event_bus_name" in rdef:
            bus = self._resolve_ref(get_refs({"bus": rdef["event_bus_name"]})[0])
        else:
            bus = "default"
        name = self.var_resolver.resolve(rdef["name"][0])
        return f"{bus}/{name}"

    def resolve_aws_cloudwatch_event_target(self, logical_id, rdef):
        rule = self._resolve_ref(get_refs({"rule": rdef["rule"]})[0])
        target_id = self.var_resolver.resolve(rdef["target_id"][0])
        ref = get_refs({"t": [target_id]})
        if ref:
            target_id = self._resolve_ref(ref[0]).split("/")[-1]
        return f"{rule}/{target_id}"

    def resolve_aws_sqs_queue_policy(self, logical_id, rdef):
        return self._resolve_ref(get_refs({"queue": rdef["queue_url"]})[0])

    def resolve_aws_security_group(self, logical_id, rdef):
        sgs = self._resolve_resources(self.get_cfn_type(logical_id))
        hcl_ident = self.var_resolver.resolve(self.get_identity(rdef))
        for s in sgs:
            if s["GroupName"] == hcl_ident:
                return s["GroupId"]

    def resolve_aws_kms_key(self, logical_id, rdef):
        desc = self._value(rdef, "description")
        if desc is None:
            return None
        desc = self.var_resolver.resolve(desc)
        resources = self._resolve_resources(self.get_cfn_type(logical_id))

        # we generally early exit, but description is a pretty weak
        # user specified identity and there are large consequences
        # wrt to storage changes on kms, so double check.
        results = []
        for r in resources:
            if r["Description"] == desc:
                results.append(r["KeyId"])
        if len(results) > 1:
            raise AmbigiousError(
                (
                    "aws_kms_key ambigious description ('%s') use identity"
                    "file.\n found multiple keys %s"
                )
                % (desc, ", ".join(results))
            )

    def resolve_aws_iam_role(self, logical_id, rdef):
        return self.var_resolver.resolve(self.get_identity(rdef))

    def resolve_aws_sqs_queue(self, logical_id, rdef):
        name = self.var_resolver.resolve(self.get_identity(rdef))
        return f"https://sqs.{self.region}.amazonaws.com/{self.account_id}/{name}"

    def resolve_aws_elasticache_subnet_group(self, logical_id, rdef):
        return self.var_resolver.resolve_identity(self.get_identity(rdef))

    def resolve_aws_db_subnet_group(self, logical_id, rdef):
        return self.var_resolver.resolve_identity(self.get_identity(rdef))

    def resolve_aws_ecs_service(self, logical_id, rdef):
        cluster = self._resolve_ref(get_refs({"cluster": rdef["cluster"]})[0])
        if cluster.startswith("arn:"):
            cluster = Arn.parse(cluster).resource
        service_name = self.var_resolver.resolve(rdef["name"][0])
        return f"{cluster}/{service_name}"

    def resolve_aws_cloudwatch_log_group(self, logical_id, rdef):
        name = self.resolve_default(logical_id, rdef)
        return f"/{name}"

    def resolve_aws_ssm_parameter(self, logical_id, rdef):
        return self.var_resolver.resolve(rdef["name"][0])


def get_diff(group, tfdir, tf_vars, tf_locals, ident_map):
    tresources, variables = get_hcl_resources(tfdir)
    sresources = get_state_resources(tfdir)
    eresources = get_env_resources(group)
    remainder = set(tresources) - set(sresources)
    log.info(
        "found %d of %d resources missing in state" % (len(remainder), len(tresources))
    )

    variables.update(tf_vars)
    variable_resolver = VariableResolver(variables, tf_locals)
    resource_resolver = ResourceResolver(
        variable_resolver, eresources, tresources, sresources, ident_map
    )
    rdiff = {}

    for r in sorted_graph(tresources):
        rdef = tresources[r]["def"]
        rname = build_resource_id(r, rdef)
        if r not in remainder:
            continue
        if r in ident_map:
            rdiff[rname] = ident_map[r]
            continue
        found = resource_resolver.resolve(r, rdef)
        if found:
            rdiff[rname] = found
        else:
            log.info("no candidates for %s\n %s", rname, rdef)
    return rdiff


def get_vars(var_files):
    tf_vars = {}
    for f in var_files:
        content = Path(f).read_text()
        if f.endswith(".tfvars"):
            data = hcl2.loads(content)
        elif f.endswith(".json"):
            data = json.loads(content)
        else:
            raise ValueError("invalid variable file format %s" % f)
        tf_vars.update(data)
    return tf_vars


@click.group()
def cli():
    """Terraform Resurrect"""
    logging.basicConfig(level=logging.INFO)


@cli.command()
@click.option("-g", "--name", required=True)
@click.option("-t", "--tags", multiple=True)
def init_group(name, tags):
    """Create a Resource Group for extant resources"""
    client = boto3.client("resource-groups")
    try:
        client.get_group(Group=name)
    except client.exceptions.NotFoundException:
        pass
    else:
        log.info(f"group {name} exists")
        return

    rtags = dict([t.split("=") for t in tags])
    query = {
        "ResourceTypeFilters": ["AWS::AllSupported"],
        "TagFilters": [{"Key": k, "Values": [v]} for k, v in rtags.items()],
    }

    client.create_group(
        Name=name,
        Description=f"{name} tfresurrect recovery",
        ResourceQuery={"Type": "TAG_FILTERS_1_0", "Query": json.dumps(query)},
    )


@cli.command()
@click.option("-d", "--tfdir", default=".")
def gen_import_config(tfdir):
    """provide a skeleton for manual imports"""
    tresources, variables = get_hcl_resources(tfdir)
    print(json.dumps({i: None for i in sorted(tresources)}, indent=2))


@cli.command()
@click.option("-d", "--tfdir", default=".")
def resource_graph(tfdir):
    """show dependencies between terraform resources"""
    tresources, variables = get_hcl_resources(tfdir)
    g = get_graph(tresources)
    order = sorted_graph(tresources)
    # rebuild graph dict in sorted dep order
    print(json.dumps({o: g[o] for o in order}, indent=2))


@cli.command()
@click.option("-g", "--group", required=True)
@click.option("-d", "--tfdir", default=".")
@click.option("-f", "--vars-file", type=click.Path(), multiple=True)
@click.option("-l", "--locals-file", type=click.Path(), multiple=True)
@click.option("-i", "--ident-map", type=click.Path())
def diff(group, tfdir, vars_file, locals_file, ident_map):
    """Three way diff"""
    load_resources(("aws.*",))

    tf_vars = get_vars(vars_file)
    tf_locals = get_vars(locals_file)
    if ident_map:
        ident_map = filter_empty(json.loads(Path(ident_map).read_text()))
    rdiff = get_diff(group, tfdir, tf_vars, tf_locals, ident_map or ())
    if not rdiff:
        log.info("no diff found")
    else:
        log.info("found %d importable resources" % len(rdiff))
    pprint.pprint(rdiff)


@cli.command(name="env-resources")
@click.option("-g", "--group")
def show_env_resources(group):
    """show resources in the resource group"""
    resources = get_env_resources(group)
    pprint.pprint(resources)


@cli.command()
@click.option("-d", "--tfdir", type=click.Path(), default=".")
@click.option("-g", "--group", required=True)
@click.option("-f", "--vars-file", type=click.Path(), multiple=True)
@click.option("-l", "--locals-file", type=click.Path(), multiple=True)
@click.option("-i", "--ident-map", type=click.Path())
def sync(tfdir, group, vars_file, locals_file, ident_map):
    """import resources"""
    tf_vars = get_vars(vars_file)
    tf_locals = get_vars(locals_file)

    if ident_map:
        ident_map = filter_empty(json.loads(Path(ident_map).read_text()))
    load_resources(("aws.*",))

    rdiff = get_diff(group, tfdir, tf_vars, tf_locals, ident_map or ())
    if not rdiff:
        return
    pprint.pprint(rdiff)
    args = ["terraform", "import", "-input=false", "-no-color"]
    for f in vars_file:
        args.append("-var-file=%s" % f)

    for logical_id, physical_id in rdiff.items():
        log.info("importing %s from %s\n %s", logical_id, physical_id, args)
        iargs = list(args)
        iargs.append(logical_id)
        iargs.append(physical_id)
        try:
            subprocess.check_call(iargs)
        except subprocess.CalledProcessError as e:
            print("error on %s %s\n %s" % (logical_id, physical_id, str(e)))


if __name__ == "__main__":
    try:
        cli()
    except (SystemExit, AmbigiousError):
        raise
    except:  # noqa
        import traceback, sys, pdb  # noqa

        traceback.print_exc()
        pdb.post_mortem(sys.exc_info()[-1])
