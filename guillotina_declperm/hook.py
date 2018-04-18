from itertools import chain
import logging

from guillotina import app_settings, configure
from guillotina.interfaces import (IResource, IObjectAddedEvent,
                                   IObjectModifiedEvent, IObjectRemovedEvent)
from guillotina.utils import get_current_request, navigate_to
from guillotina.transactions import get_tm

from . import compiler

log = logging.getLogger(__name__)


async def get_object_by_oid(oid, txn):
    '''
     Need to do a reverse lookup of the object to all the parents
     '''
    result = txn._manager._hard_cache.get(oid, None)
    if result is None:
        result = await txn._get(oid)

    obj = reader(result)
    obj._p_jar = txn
    if result['parent_id']:
        obj.__parent__ = await get_object_by_oid(result['parent_id'], txn)
    return obj


def get_rules():
    return chain(*app_settings['permissions'].values())


async def before_commit(txn):
    # gather all added/modified objects, and removed ones.
    added, modified, deleted = (list(txn.added.values()),
                                list(txn.modified.values()),
                                list(txn.deleted.values()))
    # register the post_commit hook if necessary
    if added or modified or deleted:
        txn.add_after_commit_hook(after_commit, txn, added, modified, deleted)


async def after_commit(success, txn, added, modified, deleted):
    if not success:
        return

    need_update = added + modified

    # TODO find objects where acls need recalc as a secondary effect of the add/mod/del)

    tm = get_tm()
    txn = await tm.begin()
    txn.guillotina_declperm_marker = True

    rules = list(get_rules())

    try:
        for obj in need_update:
            obj = await get_object_by_oid(obj._p_oid, txn)
            await compiler.apply_perms(txn, obj, rules)
    except:
        log.exception("error applying permissions")
        await tm.abort(txn=txn)
    else:
        await tm.commit(txn=txn)


def getHook(txn):
    if getattr(txn, 'guillotina_declperm_marker', False):
        return

    txn.guillotina_declperm_marker = True
    txn.add_before_commit_hook(before_commit, txn)


@configure.subscriber(for_=(IResource, IObjectAddedEvent))
@configure.subscriber(for_=(IResource, IObjectModifiedEvent))
@configure.subscriber(for_=(IResource, IObjectRemovedEvent))
def check_for_hook(obj, event):
    getHook(get_current_request()._txn)
