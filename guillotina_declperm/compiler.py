import itertools

from guillotina.api.content import PermissionMap
from guillotina.auth.role import local_roles
from guillotina.auth.users import ROOT_USER_ID
from guillotina.event import notify
from guillotina.events import ObjectPermissionsModifiedEvent
from guillotina.exceptions import PreconditionFailed
from guillotina.interfaces import IPrincipalPermissionManager
from guillotina.interfaces import IPrincipalRoleManager
from guillotina.interfaces import IRolePermissionManager

import logging

log = logging.getLogger(__name__)


async def get_resources_matching(txn, match):
    if '@type' not in match:
        raise ValueError('match does not contain a @type')
    async for res in txn._get_resources_of_type(match['@type']):
        yield res


def match(obj, match):
    if obj.type_name == match.get('@type'):
        return True
    return False


def rule_match(obj, rule):
    return any(match(obj, m) for m in rule['match'])


async def expand_expr(txn, obj, expr):
    if isinstance(expr, list):
        r = list(
            itertools.chain(*[ await expand_expr(txn, obj, e) for e in expr]))
        return r
    if isinstance(expr, dict):
        expanded = []
        async for res in get_resources_matching(txn, expr['match']):
            res = txn._fill_object(res, None)
            expanded.extend(await expand_expr(txn, res, expr['expr']))
        return expanded
    if expr.startswith('{') and expr.endswith('}'):
        expr = expr[1:-1]
        if not expr.startswith('.'):
            raise NotImplemented(
                "Only expressions starting with a '.' are supported")
        attrname = expr[1:]
        if '.' in attrname:
            raise NotImplemented("deep expressions")
        value = getattr(obj, attrname)
        if isinstance(value, list):
            # we assume items are strings. In a later version we should enforce
            # it.
            return value
        return [value]
    else:
        return [expr]


async def expand_rule(txn, obj, sharing):
    res = {'prinrole': [], 'prinperm': [], 'roleperm': []}

    for prinrole in sharing.get('prinrole', ()):
        for principal in await expand_expr(txn, obj, prinrole['principal']):
            for role in await expand_expr(txn, obj, prinrole['role']):
                for setting in await expand_expr(txn, obj,
                                                 prinrole['setting']):
                    res['prinrole'].append({
                        "principal": principal,
                        "role": role,
                        "setting": setting
                    })

    for prinperm in sharing.get('prinperm', ()):
        for principal in await expand_expr(txn, obj, prinrole['principal']):
            for permission in await expand_expr(txn, obj,
                                                prinrole['permission']):
                for setting in await expand_expr(txn, obj,
                                                 prinrole['setting']):
                    res['prinperm'].append({
                        "principal": principal,
                        "permission": permission,
                        "setting": setting
                    })

    for roleperm in sharing.get('roleperm', ()):
        for role in await expand_expr(txn, obj, roleperm['role']):
            for permission in await expand_expr(txn, obj,
                                                roleperm['permission']):
                for setting in await expand_expr(txn, obj,
                                                 roleperm['setting']):
                    res['roleperm'].append({
                        "role": role,
                        "permission": permission,
                        "setting": setting
                    })

    return res


async def compile_rules(txn, obj, rules):
    res = {'prinrole': [], 'prinperm': [], 'roleperm': []}

    for rule in rules:
        rule = await expand_rule(txn, obj, rule)
        res['prinrole'].extend(rule['prinrole'])
        res['prinperm'].extend(rule['prinperm'])
        res['roleperm'].extend(rule['roleperm'])

    return res


async def calc_perms(txn, obj, rules):
    matching_rules = [
        rule['sharing'] for rule in rules if rule_match(obj, rule)
    ]

    return await compile_rules(txn, obj, matching_rules)


async def apply_perms(txn, obj, rules):
    # gather matching rules

    perms = await calc_perms(txn, obj, rules)

    # find rules of other types having expressions matching the obj
    # expand those expressions with the obj and add the perms to
    # the other objects

    await resetPerms(obj, perms)


async def resetPerms(obj, perms):
    obj.__acl__ = None
    await addPerms(obj, perms, True)


async def addPerms(obj, perms, changed=False):
    """apply some permissions. Copied almost verbatim from sharingPOST service"""
    lroles = local_roles()
    if 'prinrole' not in perms and \
            'roleperm' not in perms and \
            'prinperm' not in perms:
        raise PreconditionFailed(obj,
                                 'prinrole or roleperm or prinperm missing')

    for prinrole in perms.get('prinrole') or []:
        setting = prinrole.get('setting')
        if setting not in PermissionMap['prinrole']:
            raise PreconditionFailed(obj, 'Invalid Type {}'.format(setting))
        manager = IPrincipalRoleManager(obj)
        operation = PermissionMap['prinrole'][setting]
        func = getattr(manager, operation)
        if prinrole['role'] in lroles:
            changed = True
            func(prinrole['role'], prinrole['principal'])
        else:
            raise PreconditionFailed(obj, 'No valid local role')

    for prinperm in perms.get('prinperm') or []:
        setting = prinperm['setting']
        if setting not in PermissionMap['prinperm']:
            raise PreconditionFailed(obj, 'Invalid Type')
        manager = IPrincipalPermissionManager(obj)
        operation = PermissionMap['prinperm'][setting]
        func = getattr(manager, operation)
        changed = True
        func(prinperm['permission'], prinperm['principal'])

    for roleperm in perms.get('roleperm') or []:
        setting = roleperm['setting']
        if setting not in PermissionMap['roleperm']:
            raise PreconditionFailed(obj, 'Invalid Type')
        manager = IRolePermissionManager(obj)
        operation = PermissionMap['roleperm'][setting]
        func = getattr(manager, operation)
        changed = True
        func(roleperm['permission'], roleperm['role'])

    if changed:
        obj._p_register()  # make sure data is saved
        await notify(ObjectPermissionsModifiedEvent(obj, perms))
