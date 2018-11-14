import logging

from guillotina import configure
from guillotina.api.service import Service
from guillotina.interfaces import IResource

from . import compiler
from .utils import get_rules

log = logging.getLogger(__name__)


@configure.service(
    context=IResource,
    name="@recalc_sharing",
    method="POST",
    permission="guillotina.ChangePermissions",
)
class Login(Service):
    async def __call__(self):
        await compiler.apply_perms(
            self.request._txn, self.context, get_rules()
        )
        return {}
