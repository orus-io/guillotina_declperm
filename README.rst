guillotina_declperm
===================

Provide declarative permissions for guillotina.

Allow to provide centralized declarative definitions of all the permissions
of a data model, including rules that will use the object data to build complex
permission settings.

A 'permissions' configuration entry can be completed by the configuration or
any application. It is a dictionnary so the different configurations are merged.
The key will be ignored and the value is a list of permission rules.

A permission rule is a dict with:

match
    A list of matching expression. Example '{"@type": "User"}' will match any 
    resource with type_name=='User'

sharing
    A 'roleperm', 'prinrole', 'prinperm' dictionnary, which is a superset of
    the basic acl lists of guillotina.

    Each value can be:

    list of string
        The current access rule (the item in the 'roleperm' list for example)
        will be copied for each value of the list.
        Each value can itself be an expression that will be expanded too.

    "{.xxx}"
        Will be replaced by the value of the 'xxx' attribute of the object.
        If the value is a list, the current access rule will be copied for each
        value found in the list.

    "somestring"
        will be copied as is.

Example in yaml:

.. code-block:: yaml

    permissions:
      my-permission-set:
        - match:
            - @type: 'Container'
          sharing:
            prinrole:
              - principal:
                  match:
                    @type: User
                  expr: {.id}
                role: myapp.ClientProfile
                setting: Allow
              - principal: root
                role:
                  - guillotina.ContainerAdmin
                  - guillotina.Owner
                setting: Allow
            roleperm:
              - role: myapp.ClientProfile
                permission:
                  - guillotina.AccessContent
                  - guillotina.ViewContent
                setting: Allow
