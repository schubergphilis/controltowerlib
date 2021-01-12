=====
Usage
=====


To develop on controltowerlib:

.. code-block:: bash

    # The following commands require pipenv as a dependency

    # To lint the project
    _CI/scripts/lint.py

    # To execute the testing
    _CI/scripts/test.py

    # To create a graph of the package and dependency tree
    _CI/scripts/graph.py

    # To build a package of the project under the directory "dist/"
    _CI/scripts/build.py

    # To see the package version
    _CI/scripts/tag.py

    # To bump semantic versioning [--major|--minor|--patch]
    _CI/scripts/tag.py --major|--minor|--patch

    # To upload the project to a pypi repo if user and password are properly provided
    _CI/scripts/upload.py

    # To build the documentation of the project
    _CI/scripts/document.py


To use controltowerlib in a project:

.. code-block:: python

    from controltowerlib import ControlTower
    tower = ControlTower('arn:aws:iam::ACCOUNTID:role/ValidAdministrativeRole')

    for account in tower.accounts:
        print(account.name)
    >>> root
        Audit
        Log archive

    for account in tower.accounts:
        print(account.guardrail_compliance_status)
    >>> COMPLIANT
        COMPLIANT
        COMPLIANT

    for ou in tower.organizational_units:
        print(ou.name)
    >>> Custom
        Core
        Root

    tower.create_organizational_unit('TestOU')
    >>> True

    tower.delete_organizational_unit('TestOU')
    >>> True
