import logging
import sys
from datetime import timedelta
import asyncio
from typing import Callable, Tuple
import base64

import webexteamssdk

from .webexteamsasyncapi import WebexTeamsAsyncAPI
from .interactive import Token

log = logging.getLogger(__name__)

class MyException(Exception):
    pass

async def as_get_uuids(access_token: str, running: Callable[[], bool]):
    api = WebexTeamsAsyncAPI(access_token)
    people = []
    async for pp in api.list_people(p_max=100):
        people.append(pp)

    for r in people:
        print("User email: %-30s UUID: %-40s" % (r.emails[0], base64.b64decode(r.id+'==').decode('utf-8').split('/')[-1]))
    return


def get_uuids(sid: str, running: Callable[[], bool], user_id: str):
    # add a logging handler to stdout; logging output will be sent to the client via websocket
    format = logging.Formatter(fmt='{levelname:8s} get_uuids: {message}', style='{')
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setLevel(logging.ERROR)
    handler.setFormatter(format)
    log.addHandler(handler)

    try:
        log.debug(f'user_id={user_id}, sid={sid}')

        # First get an access token
        log.debug(f'trying to get access token')
        access_token = Token.get_token(user_id=user_id)
        if access_token is None:
            log.error(f'Failed to get access token for {user_id}')
            raise MyException

        lifetime_remaining = timedelta(seconds=access_token.lifetime_remaining_seconds)
        log.debug(f'access token still valid for {lifetime_remaining}')

        # need to make sure that the access token is good for another 10 minutes
        if lifetime_remaining.total_seconds() < 600:
            access_token.refresh()
            log.debug(
                f'had to refresh access token. New lifetime: '
                f'{timedelta(seconds=access_token.lifetime_remaining_seconds)}')

        # run asynchronous task 
        asyncio.run(as_get_uuids(access_token.access_token, running))
        return

    except MyException:
        pass
    finally:
        # cleanup
        log.debug('cleaning up...')
        log.removeHandler(handler)
        print('-------------- Done ----------')
