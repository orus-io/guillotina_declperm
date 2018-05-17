from itertools import chain
import logging

from guillotina import configure
from guillotina.interfaces import (IResource, IObjectAddedEvent,
                                   IObjectModifiedEvent, IObjectRemovedEvent)
from guillotina.utils import get_current_request, navigate_to
from guillotina.transactions import get_tm
from guillotina.db.reader import reader
from guillotina.db.transaction import HARD_CACHE

from .utils import get_rules

from . import compiler

log = logging.getLogger(__name__)


async def get_object_by_oid(oid, txn):
    '''
     Need to do a reverse lookup of the object to all the parents
     '''
    result = HARD_CACHE.get(oid, None)
    if result is None:
        result = await txn._get(oid)

    return await load_res(result, txn)


async def load_res(result, txn):
    obj = reader(result)
    obj._p_jar = txn
    if result['parent_id']:
        obj.__parent__ = await get_object_by_oid(result['parent_id'], txn)
    return obj


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

    rules = list(get_rules())

    need_update = added + modified

    reverse_update_matches = []
    for m in chain(*[
            compiler.need_reverse_update(obj, rules)
            for obj in (added + modified + deleted)
    ]):
        if m not in reverse_update_matches:
            reverse_update_matches.append(m)

    tm = get_tm()
    txn = await tm.begin()
    txn.guillotina_declperm_marker = True

    done = {}

    try:
        for obj in need_update:
            obj = await get_object_by_oid(obj._p_oid, txn)
            await compiler.apply_perms(txn, obj, rules)
            done[obj._p_oid] = obj

        for match in reverse_update_matches:
            async for res in compiler.get_resources_matching(txn, match):
                if res['zoid'] in done:
                    continue
                obj = await get_object_by_oid(res['zoid'], txn)
                await compiler.apply_perms(txn, obj, rules)
                done[obj._p_oid] = obj

    except:
        log.exception("error applying permissions")
        await tm.abort(txn=txn)
    else:
        log.debug("applied permissions successfully")
        await tm.commit(txn=txn)


def getHook(txn):
    for hook, _, _ in txn._before_commit:
        if hook == before_commit:
            return

    txn.add_before_commit_hook(before_commit, txn)


@configure.subscriber(for_=(IResource, IObjectAddedEvent))
@configure.subscriber(for_=(IResource, IObjectModifiedEvent))
@configure.subscriber(for_=(IResource, IObjectRemovedEvent))
def check_for_hook(obj, event):
    getHook(get_current_request()._txn)
