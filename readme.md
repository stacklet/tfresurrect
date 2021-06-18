

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

let's look at the resources we have extant

```
tfresurrect env-resources -g assetdb-sandbox
```

now let's look at the diff of things we can import

```
tfresurrect env-resources -g assetdb-sandbox
```

and finally let's import resources
```
tfresurrect import -g assetdb-sandbox
```

