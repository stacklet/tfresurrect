import boto3
import click
from collections import defaultdict
from graphlib import TopologicalSorter
from c7n.resources import load_resources
from c7n.resources.aws import Arn, AWS
from c7n.policy import Policy
from c7n.config import Config
from c7n.utils import filter_empty
import jmespath
import json
import logging
import hcl2
import pprint
from pathlib import Path
import re
import subprocess


__author__ = "Kapil Thangavelu <kapil@stacklet.io>"


log = logging.getLogger("tfresurrect")


class AmbigiousError(ValueError):
    pass


def get_env_resources(group):
    # https://docs.aws.amazon.com/ARG/latest/userguide/supported-resources.html
    # lots of notables, iam roles, lambda layers, ecs services, etc
    client = boto3.client("resource-groups")
    group_resources = client.list_group_resources(Group=group).get(
        "ResourceIdentifiers"
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

    for tf in Path(str(tf_dir)).rglob("**/*.tf"):
        tf_data = hcl2.loads(tf.read_text())
        for r in tf_data.get("resource", ()):
            rtype = list(r.keys()).pop()
            for rname in r[rtype].keys():
                rdef = r[rtype][rname]
                resources[f"{rtype}.{rname}"] = {"def": rdef}

    for tfjson in Path(str(tf_dir)).rglob("**/*.tf.json"):
        tf_data = json.loads(tfjson.read_text())
        for rtype, rset in tf_data.get("resource").items():
            for rname, rdef in rset.items():
                resources[f"{rtype}.{rname}"] = {"def": arrayify(rdef)}
    return resources


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
    return graph


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
        ident = self._resolve_variables(ident)
        ident = self._resolve_locals(ident)
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
        "aws::elasticache::subnet_group": "aws::elasticache::subnetgroup",
    }

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

        # dynamic lookup
        self.rmanager = Policy(
            {"name": "resolver", "resource": "aws.ec2"}, Config.empty()
        ).resource_manager

    def get_cfn_type(self, logical_id):
        provider, rservice, rtype = logical_id.split(".", 1)[0].split("_", 2)
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
        else:
            raise ValueError("unknown logical id %s" % logical_id)

    def _resolve_resources(self, cfn_type, rids=None):
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
        if not rids:
            candidates = self.eresources.get(cfn_type, ())
            if not candidates:
                return None
            rids = [Arn.parse(c).resource for c in candidates]
        resources = kmanager.get_resources(rids)
        self._resource_cache[cfn_type] = resources
        return resources

    def _value(self, rdef, key):
        v = rdef.get(key)
        if isinstance(v, list):
            return v[0]

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

    def resolve_aws_cloudwatch_event_target(self, logical_id, rdef):
        rule = self._resolve_ref(get_refs({"rule": rdef["rule"]})[0])
        target_id = self.var_resolver.resolve(rdef["target_id"][0])
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
        return self.var_resolver.resolve_identity(self.get_identity(rdef))

    def resolve_aws_sqs_queue(self, logical_id, hcl_ident):
        arn = self.resolve_default(logical_id, hcl_ident, arn=True)
        if not arn:
            return arn
        p = Arn.parse(arn)
        return f"https://sqs.{p.region}.amazonaws.com/{p.account_id}/{p.resource}"

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


def get_diff(group, tfdir, tf_vars, tf_locals, ident_map):
    tresources = get_hcl_resources(tfdir)
    sresources = get_state_resources(tfdir)
    eresources = get_env_resources(group)
    remainder = set(tresources) - set(sresources)
    log.info(
        "found %d of %d resources missing in state" % (len(remainder), len(tresources))
    )

    variable_resolver = VariableResolver(tf_vars, tf_locals)
    resource_resolver = ResourceResolver(
        variable_resolver, eresources, tresources, sresources, ident_map
    )
    rdiff = {}

    for r in sorted_graph(tresources):
        if r not in remainder:
            continue
        if r in ident_map:
            rdiff[r] = ident_map[r]
            continue
        rdef = tresources[r]["def"]
        found = resource_resolver.resolve(r, rdef)
        if found:
            rdiff[r] = found
        else:
            log.info("no candidates for %s\n %s", r, rdef)
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
    tresources = get_hcl_resources(tfdir)
    print(json.dumps({i: None for i in sorted(tresources)}, indent=2))


@cli.command()
@click.option("-d", "--tfdir", default=".")
def resource_graph(tfdir):
    """show dependencies between terraform resources"""
    tresources = get_hcl_resources(tfdir)
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
        subprocess.check_call(iargs)


if __name__ == "__main__":
    try:
        cli()
    except (SystemExit, AmbigiousError):
        raise
    except:  # noqa
        import traceback, sys, pdb  # noqa

        traceback.print_exc()
        pdb.post_mortem(sys.exc_info()[-1])
