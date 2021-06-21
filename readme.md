# Terraform Resurrect

A lifeline for when you lose your state, and go uhoh.

Attempts to reconstruct a terraform state from the environment
by performing a three way diff and import.

Assumptions
 - aws provider 
 - resources in the environment have some set of tags

Don't panic :-)

# Usage

Create a resource group to identify extant things in the environment
that were created by terraform.

```
tfresurrect init-group -g assetdb-sandbox -t "Env=sandbox" -t "App=AssetDB" -t "Owner=kapil@stacklet.io"
```

let's look at the resources we are able to discover using tags

```
tfresurrect env-resources -g assetdb-sandbox
```

now let's look at the diff of things we can import

```
tfresurrect diff -g assetdb-sandbox -f settings.tfvars
```

in some cases we won't be able to fully import all the resources unless we specify
mappings of terraform resources to physical resources manually. tfresurrect
can generate a mapping file for us to fill in

```
tfresurrect gen-identity
```

we can pass the identity file to `sync` and `diff` commands via `-i identify_file.json`

and finally let's import missing resources
```
tfresurrect sync -g assetdb-sandbox -f settings.tfvar -i identity.json
```

