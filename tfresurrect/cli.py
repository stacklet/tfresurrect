import boto3
import click
from c7n.resources.aws import Arn
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
        # print(tf.name)
        tf_data = hcl2.loads(tf.read_text())
        # print(tf_data.keys())
        for r in tf_data.get("resource", ()):
            rtype = list(r.keys()).pop()
            for rname in r[rtype].keys():
                rdef = r[rtype][rname]
                physical_id = None
                if "name" in rdef:
                    physical_id = rdef["name"]
                elif "identifier" in rdef:
                    physical_id = rdef["id"]
                else:
                    # print(f'no identifier for {rtype}.{rname} \n {rdef}')
                    continue
                resources[f"{rtype}.{rname}"] = physical_id
    return resources


def get_diff(group, tfdir, tf_vars, ident_map):
    tresources = get_hcl_resources(tfdir)
    sresources = get_state_resources(tfdir)
    eresources = get_env_resources(group)
    remainder = set(tresources) - set(sresources)

    log.info(
        "found %d of %d resources missing in state" % (len(remainder), len(tresources))
    )

    rdiff = {}
    for r in sorted(remainder, key=lambda x: len(x), reverse=True):
        provider, rservice, rtype = r.split(".", 1)[0].split("_", 2)
        # print(f"{rservice} {rtype} {tresources[r]}")
        cfn_type = get_env_type(provider, rservice, rtype)
        ident = tresources[r]
        ident = ident and ident[0]

        if "var." in ident or "local." in ident:
            # log.info('variable in identity %s -> %s', r, ident)
            rident = resolve_ident_variable(ident, tf_vars)
            # log.info('resolve identity %s -> %s', ident, rident)
            ident = rident

        if ident in ident_map:
            found = ident_map[found]
        else:
            found = resolve_resource(eresources, cfn_type, r, ident, ident_map)
        if found:
            rdiff[r] = found
        else:
            log.info("no candidates for %s %s", r, ident)
    return rdiff


def resolve_resource(eresources, cfn_type, r, ident, ident_map):
    # iam roles aren't returned by resource group tagging :(
    # elasticache cache subnet groups :(
    # ecs-services aren't returned

    if cfn_type in ("aws::iam::role", "aws::elasticache::subnetgroup"):
        return ident

    if cfn_type not in eresources:
        log.info("no type candidates for %s %s", cfn_type, r)
        return

    candidates = eresources[cfn_type]
    found = False
    for c in candidates:
        if ident in c:
            found = c
            break
    return found


def get_regex(name, var=False, local=False):
    assert var or local

    if var:
        return re.compile("((?:\$\{)?var[.]" + name + "(?:\})?)")
    if local:
        return re.compile("((?:\$\{)?local[.]" + name + "(?:\})?)")


def resolve_ident_variable(ident, tf_vars):
    for k in sorted(tf_vars.keys(), key=lambda x: len(x), reverse=True):
        if k == "locals":
            continue
        if f"var.{k}" not in ident:
            continue
        regex = get_regex(k, var=True)
        v = tf_vars[k]
        if isinstance(v, list):
            v = v[0]
        ident = regex.sub(v, ident)

    for k in sorted(
        tf_vars.get("locals", {}).keys(), key=lambda x: len(x), reverse=True
    ):
        if f"local.{k}" not in ident:
            continue
        v = tf_vars["locals"][k]
        if isinstance(v, list):
            v = v[0]
        regex = get_regex(k, local=True)
        ident = regex.sub(v, ident)
    return ident


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
        if "locals" in data:
            tf_vars.setdefault("locals", {}).update(data.pop("locals"))
        tf_vars.update(data)
    return tf_vars


@cli.command()
@click.option("-g", "--group", required=True)
@click.option("-d", "--tfdir", default=".")
@click.option("-f", "--vars-file", type=click.Path(), multiple=True)
@click.option("-i", "--ident-map", type=click.Path())
def diff(group, tfdir, vars_file, ident_map):
    """Three way diff

    environment resources
    terraform state file
    terraform hcl
    """
    tf_vars = get_vars(vars_file)
    if ident_map:
        ident_map = json.loads(Path(ident_map).read_text())
    rdiff = get_diff(group, tfdir, tf_vars, ident_map or ())
    if not rdiff:
        log.info("no diff found")
    else:
        log.info("found %d importable resources" % len(rdiff))
    pprint.pprint(rdiff)


TRANSLATOR_MAP = {
    "aws::security::group": "aws::ec2::securitygroup",
    "aws::db::instance": "aws::rds:dbinstance",
    "aws::cloudwatch::event_rule": "aws::events::rule",
    "aws::cloudwatch::log_group": "aws::logs::loggroup",
    "aws::elasticache::subnet_group": "aws::elasticache::subnetgroup",
}


def get_env_type(provider, rservice, rtype):
    etype = f"{provider}::{rservice}::{rtype}"
    return TRANSLATOR_MAP.get(etype, etype)

ARN_IMPORTS = set(
    ('sqs', '')
)

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
@click.option("-i", "--ident-map", type=click.Path())
def sync(tfdir, group, vars_file, ident_map):
    tf_vars = get_vars(vars_file)
    if ident_map:
        ident_map = json.loads(Path(ident_map).read_text())
    rdiff = get_diff(group, tfdir, tf_vars, ident_map or ())

    if not rdiff:
        return

    args = ["terraform", "import", '-input=false', '-no-color']
    for f in vars_file:
        args.append('-var-file=%s' % f)

    for logical_id, physical_id in rdiff.items():
        log.info('importing %s from %s\n %s', logical_id, physical_id, args)
        iargs = list(args)
        iargs.append(logical_id)

        if physical_id.startswith('arn:'):
            parsed_arn = Arn.parse(physical_id)
            if (parsed_arn.service, parsed_arn.resource_type) not in ARN_IMPORTS:
                iargs.append(Arn.parse(physical_id).resource)
            else:
                iargs.append(physical_id)
        else:
            iargs.append(physical_id)
        subprocess.check_call(iargs)


if __name__ == "__main__":
    try:
        cli()
    except SystemExit:
        raise
    except:
        import traceback, sys, pdb

        traceback.print_exc()
        pdb.post_mortem(sys.exc_info()[-1])
