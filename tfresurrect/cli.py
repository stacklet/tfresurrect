import boto3
import click
from collections import defaultdict
from graphlib import TopologicalSorter
from c7n.resources import load_resources
from c7n.resources.aws import Arn, ArnResolver
from c7n.policy import Policy
from c7n.config import Config
import jmespath
import json
import logging
import hcl2
import os
import pprint
from pytest_terraform.tf import TerraformRunner as BaseRunner
from pathlib import Path
import re
import subprocess

log = logging.getLogger("tfresurrect")


# this feels mostly superflous just call show directly and skip the dep
class TerraformRunner(BaseRunner):

    command_templates = dict(BaseRunner.command_templates)
    command_templates["show"] = "show -json"
    command_templates[
        "import"
    ] = "import {input} {color} {var_file} {logical_id} {physical_id}"

    def show(self):
        args = self._get_cmd_args("show")
        return json.loads(
            subprocess.check_output(
                args, cwd=os.path.abspath(self.module_dir or self.work_dir)
            )
        )


def get_env_resources(group):
    # https://docs.aws.amazon.com/ARG/latest/userguide/supported-resources.html
    # lots of notables, iam roles, lambda layers, ecs services, etc
    client = boto3.client("resource-groups")
    group_info = client.get_group(Group=group).get("Group")
    group_resources = client.list_group_resources(Group=group).get(
        "ResourceIdentifiers"
    )

    env_resources = {}
    for r in group_resources:
        env_resources.setdefault(r["ResourceType"].lower(), []).append(r["ResourceArn"])
    return env_resources


def get_state_resources(tf_dir):
    runner = TerraformRunner(work_dir=tf_dir, module_dir=tf_dir, tf_bin="terraform")
    state = runner.show()
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
        print(tf.name)
        tf_data = hcl2.loads(tf.read_text())
        print(tf_data.keys())
        for r in tf_data.get("resource", ()):
            rtype = list(r.keys()).pop()
            for rname in r[rtype].keys():
                rdef = r[rtype][rname]
                physical_id = None
                if "name" in rdef:
                    physical_id = rdef["name"]
                elif "identifier" in rdef:
                    physical_id = rdef["id"]
                elif "family" in rdef:
                    physical_id = rdef["family"]
                elif "description" in rdef:
                    physical_id = rdef["description"]
                else:
                    # print(f'no identifier for {rtype}.{rname} \n {rdef}')
                    continue
                resources[f"{rtype}.{rname}"] = {"id": physical_id[0], "def": rdef}
    return resources


class ResourceResolver:
    """Resolve an a terraform hcl identifier to an importable resource id"""

    hcl_cfn_type_map = {
        "aws::security::group": "aws::ec2::securitygroup",
        "aws::db::instance": "aws::rds::dbinstance",
        "aws::cloudwatch::event_rule": "aws::events::rule",
        "aws::cloudwatch::log_group": "aws::logs::loggroup",
        "aws::elasticache::subnet_group": "aws::elasticache::subnetgroup",
    }

    arn_imports = set()

    def __init__(self, eresources, tresources, tstate, ident_map):
        self.eresources = eresources
        self.tresources = tresources
        self.tstate = tstate
        self.ident_map = ident_map
        self.rmanager = Policy(
            {"name": "resolver", "resource": "aws.ec2"}, Config.empty()
        ).resource_manager
        self.arn_resolver = ArnResolver(self.rmanager)

    def get_cfn_type(self, logical_id):
        provider, rservice, rtype = logical_id.split(".", 1)[0].split("_", 2)
        etype = f"{provider}::{rservice}::{rtype}"
        return self.hcl_cfn_type_map.get(etype, etype)

    def resolve(self, logical_id, hcl_ident):
        # logical_id == aws_sqs_queue.trail_event_queue
        # hcl_ident = name/id attribute with block, post variable resolution

        named_handler = "resolve_%s" % logical_id.split(".", 1)[0]
        resolver = getattr(self, named_handler, self.resolve_default)

        result = resolver(logical_id, hcl_ident)
        if result is None:
            # and not logical_id.split('.', 1)[0] in (
            #    'aws_kms_alias', 'aws_iam_role_policy'):
            print(f"resolve {logical_id} {hcl_ident} failed")
        return result

    def resolve_default(self, logical_id, hcl_ident, arn=False, multi=False):
        # only works for things that are supported by aws resource group tagging.
        # - iam roles aren't returned by resource group tagging :(
        # - elasticache cache subnet groups :(
        # - ecs-services aren't returned
        #
        # review full sadness on partial support
        # https://docs.aws.amazon.com/ARG/latest/userguide/supported-resources.html
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

    def resolve_aws_security_group(self, logical_id, hcl_ident):
        candidates = self.resolve_default(logical_id, hcl_ident, multi=True)
        sgs = self.rmanager.get_resource_manager("aws.security-group").get_resources(
            [Arn.parse(c).resource for c in candidates]
        )
        for s in sgs:
            if s["GroupName"] == hcl_ident:
                return s["GroupId"]
        print(sgs)

    def resolve_aws_iam_role(self, logical_id, hcl_ident):
        return hcl_ident

    def resolve_aws_sqs_queue(self, logical_id, hcl_ident):
        arn = self.resolve_default(logical_id, hcl_ident, arn=True)
        if not arn:
            return arn
        p = Arn.parse(arn)
        return f"https://sqs.{p.region}.amazonaws.com/{p.account_id}/{p.resource}"

    def resolve_aws_elasticache_subnet_group(self, logical_id, hcl_ident):
        return hcl_ident

    def resolve_aws_db_subnet_group(self, logical_id, hcl_ident):
        return hcl_ident

    def resolve_aws_ecs_service(self, logical_id, hcl_ident):
        rdef = self.tresources[logical_id]["def"]
        cluster_id = rdef.get("cluster", ["default"])[0]
        return None
        return f"{cluster_id}/{hcl_ident}"

    def resolve_aws_cloudwatch_log_group(self, logical_id, hcl_ident):
        name = self.resolve_default(logical_id, hcl_ident)
        return f"/{name}"


def sorted_graph(tresources):
    """sort the dependencies by the resource graph dependency order"""
    graph = defaultdict(list)
    for t in tresources:
        tdef = tresources[t]["def"]
        for r in get_refs(tdef):
            if not r.startswith("aws"):
                continue
            graph[t].append(r)

    pprint.pprint(graph)
    ts = TopologicalSorter(graph)
    sorder = list(ts.static_order())
    # kms keys have no real user managed identity, minus an alias
    # we can bind their identity from their aliases, so resort aliases
    # first, by just moving kms keys to the rear
    rorder = [t for t in sorder if not t.startswith("aws_kms_key")]
    [rorder.append(t) for t in sorder if t.startswith("aws_kms_key")]
    pprint.pprint(rorder)
    return rorder


TF_REF_REGEX = re.compile("\$\{(?P<ref>.*?)\}")


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


def get_diff(group, tfdir, tf_vars, tf_locals, ident_map):
    tresources = get_hcl_resources(tfdir)
    sresources = get_state_resources(tfdir)
    eresources = get_env_resources(group)
    remainder = set(tresources) - set(sresources)
    log.info(
        "found %d of %d resources missing in state" % (len(remainder), len(tresources))
    )
    resource_resolver = ResourceResolver(eresources, tresources, sresources, ident_map)
    rdiff = {}

    for r in sorted_graph(tresources):
        # print(f"{rservice} {rtype} {tresources[r]}")
        ident = tresources[r]["id"]
        if "var." in ident or "local." in ident:
            rident = resolve_ident_variable(ident, tf_vars, tf_locals)
            # log.info('resolve identity %s -> %s', ident, rident)
            ident = rident

        found = resource_resolver.resolve(r, ident)
        if found:
            rdiff[r] = found
        else:
            log.info("no candidates for %s %s", r, ident)
    return rdiff


def get_regex(name, var=False, local=False):
    assert var or local
    if var:
        return re.compile("((?:\$\{)?var[.]" + name + "(?:\})?)")
    if local:
        return re.compile("((?:\$\{)?local[.]" + name + "(?:\})?)")


def resolve_ident_variable(ident, tf_vars, tf_locals):
    for k in sorted(tf_vars.keys(), key=lambda x: len(x), reverse=True):
        if f"var.{k}" not in ident:
            continue
        regex = get_regex(k, var=True)
        v = tf_vars[k]
        if isinstance(v, list):
            v = v[0]
        ident = regex.sub(v, ident)

    for k in sorted(tf_locals.keys(), key=lambda x: len(x), reverse=True):
        if f"local.{k}" not in ident:
            continue
        v = tf_locals[k]
        if isinstance(v, list):
            v = v[0]
        regex = get_regex(k, local=True)
        ident = regex.sub(v, ident)
    return ident


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
        group = client.get_group(Group=name)
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
    tresources = get_hcl_resources(tfdir)
    print(json.dumps({i: None for i in sorted(tresources)}, indent=2))


@cli.command()
@click.option("-g", "--group", required=True)
@click.option("-d", "--tfdir", default=".")
@click.option("-f", "--vars-file", type=click.Path(), multiple=True)
@click.option("-l", "--locals-file", type=click.Path(), multiple=True)
@click.option("-i", "--ident-map", type=click.Path())
def diff(group, tfdir, vars_file, locals_file, ident_map):
    """Three way diff

    environment resources
    terraform state file
    terraform hcl
    """
    load_resources(("aws.*",))

    tf_vars = get_vars(vars_file)
    tf_locals = get_vars(locals_file)
    if ident_map:
        ident_map = json.loads(Path(ident_map).read_text())
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

    tf_vars = get_vars(vars_file)
    tf_locals = get_vars(locals_file)

    if ident_map:
        ident_map = json.loads(Path(ident_map).read_text())
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
        # subprocess.check_call(iargs)


if __name__ == "__main__":
    try:
        cli()
    except SystemExit:
        raise
    except:
        import traceback, sys, pdb

        traceback.print_exc()
        pdb.post_mortem(sys.exc_info()[-1])
