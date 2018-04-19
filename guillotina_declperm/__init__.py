from guillotina import configure

app_settings = {"permissions": {}}


def includeme(root, settings):
    configure.scan('guillotina_declperm.hook')
    configure.scan('guillotina_declperm.service')
