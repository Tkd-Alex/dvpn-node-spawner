import bech32
import grpc
from sentinel_protobuf.sentinel.session.v2.querier_pb2 import (
    QuerySessionsForNodeRequest,
)
from sentinel_protobuf.sentinel.session.v2.querier_pb2_grpc import (
    QueryServiceStub as StubSession,
)
from sentinel_protobuf.sentinel.subscription.v2.querier_pb2 import (
    QueryPayoutsForNodeRequest,
    QuerySubscriptionsForNodeRequest,
)
from sentinel_protobuf.sentinel.subscription.v2.querier_pb2_grpc import (
    QueryServiceStub as StubSubscription,
)
from sentinel_protobuf.sentinel.subscription.v2.subscription_pb2 import NodeSubscription

from utils import format_file_size, human_time_duration, string_timestamp

# from sentinel_protobuf.sentinel.subscription.v2.payout_pb2 import Payout


ibc = {
    "ibc/31FEE1A2A9F9C01113F90BD0BBCCE8FD6BBB8585FAF109A2101827DD1D5B95B8": "SCRT",
    "ibc/A8C2D23A1E6F95DA4E48BA349667E322BD7A6C996D8A4AAE8BA72E190F3D1477": "ATOM",
    "ibc/B1C0DDB14F25279A2026BC8794E12B259F8BDA546A3C5132CCAEE4431CE36783": "DEC",
    "ibc/ED07A3391A112B175915CD8FAF43A2DA8E4790EDE12566649D0C2F97716B8518": "COSMO",
    "udvpn": "UDVPN",
}

status = [
    "Unspecified",
    "Active",
    "InactivePending",
    "Inactive",
]


def hex_to_bech32(prefix: str, hex_address: str) -> str:
    b = bytes.fromhex(hex_address)
    data = bech32.convertbits(b, 8, 5, True)
    return bech32.bech32_encode(prefix, data)


def subscriptions(sentnode: str) -> list:
    channel = grpc.insecure_channel("grpc.sentinel.co:9090")
    stub = StubSubscription(channel)

    response = stub.QuerySubscriptionsForNode(
        QuerySubscriptionsForNodeRequest(address=sentnode)
    )
    subscriptions = [
        NodeSubscription.FromString(subscription.value)
        for subscription in response.subscriptions
    ]
    return [
        {
            "id": subscription.base.id,
            "address": subscription.base.address,
            "inactive_at": string_timestamp(subscription.base.inactive_at.seconds),
            "status": status[subscription.base.status],
            "status_at": string_timestamp(subscription.base.status_at.seconds),
            "node_address": subscription.node_address,
            "gigabytes": subscription.gigabytes,
            "hours": subscription.hours,
            "deposit": {
                "denom": "dvpn"
                if subscription.deposit.denom == "udvpn"
                else ibc.get(
                    subscription.deposit.denom, subscription.deposit.denom
                ).lower(),
                "amount": round(float(subscription.deposit.amount) / 1000000, 4)
                if subscription.deposit.denom == "udvpn"
                else subscription.deposit.amount,
            },
        }
        for subscription in subscriptions
    ]


def payouts(sentnode: str) -> list:
    channel = grpc.insecure_channel("grpc.sentinel.co:9090")
    stub = StubSubscription(channel)

    response = stub.QueryPayoutsForNode(QueryPayoutsForNodeRequest(address=sentnode))
    return [
        {
            "id": payout.id,
            "address": payout.address,
            "node_address": payout.node_address,
            "hours": payout.hours,
            "next_at": string_timestamp(payout.next_at.seconds),
            "price": {
                "denom": "dvpn"
                if payout.price.denom == "udvpn"
                else ibc.get(payout.price.denom, payout.price.denom).lower(),
                "amount": round(float(payout.price.amount) / 1000000, 4)
                if payout.price.denom == "udvpn"
                else payout.price.amount,
            },
        }
        for payout in response.payouts
    ]


def sessions(sentnode: str) -> list:
    channel = grpc.insecure_channel("grpc.sentinel.co:9090")
    stub = StubSession(channel)

    response = stub.QuerySessionsForNode(QuerySessionsForNodeRequest(address=sentnode))
    return [
        {
            "id": session.id,
            "subscription_id": session.subscription_id,
            "bandwidth": {
                "upload": format_file_size(
                    int(session.bandwidth.upload), binary_system=False
                ),
                "download": format_file_size(
                    int(session.bandwidth.download), binary_system=False
                ),
            },
            "address": session.address,
            "node_address": session.node_address,
            "inactive_at": string_timestamp(session.inactive_at.seconds),
            "status_at": string_timestamp(session.status_at.seconds),
            "status": status[session.status],
            "duration": human_time_duration(session.duration.seconds),
        }
        for session in response.sessions
    ]
