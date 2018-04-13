from itertools import chain
import logging

from guillotina import app_settings, configure
from guillotina.interfaces import (IResource, IObjectAddedEvent,
                                   IObjectModifiedEvent, IObjectRemovedEvent)
from guillotina.utils import get_current_request
from guillotina.transactions import get_tm

from . import compiler

log = logging.getLogger(__name__)


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

    try:
        for obj in need_update:
            obj = await txn.get(obj._p_oid)
            await compiler.apply_perms(txn, obj, get_rules())
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
    log.debug("HEEEERE: %s, %s", obj, event)
    getHook(get_current_request()._txn)
