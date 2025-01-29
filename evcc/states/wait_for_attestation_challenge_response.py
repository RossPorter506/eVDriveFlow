"""
.. module:: wait_for_attestation_challenge_response
   :platform: Unix
   :synopsis: A module describing the AttestationChallenge state (for IAM2).

.. Copyright 2022 EDF 

.. moduleauthor:: Ross PORTER

.. License:: This source code is licensed under the MIT License.


"""

from evcc.states.ev_state import DcEVState
from shared.reaction_message import ReactionToIncomingMessage, SendMessage
import time
from shared.xml_classes.common_messages import ScheduleExchangeReq, SessionStopReq, ChargingSessionType
from shared.log import logger
from shared.xml_classes.iam import AttestationEvidenceReq, MessageHeaderType
from IAM.IAM_TEE import hash_sign_software

from ecdsa import VerifyingKey, BadSignatureError

class WaitForAttestationChallengeResponse(DcEVState):
    def __init__(self):
        super(WaitForAttestationChallengeResponse, self).__init__(name="WaitForAttestationChallengeRes")
        with open("../shared/certificates/IAM_keys/secc_public_attestation_key.pem", "r") as pub_key_file:
            self.secc_public_key = VerifyingKey.from_pem(pub_key_file.read())
        with open("../IAM/secc.sha256", "rb") as f:
            self.expected_hash = f.read()

    def process_payload(self, payload) -> ReactionToIncomingMessage:
        request = AttestationEvidenceReq()
        (request.evidence, request.signature) = hash_sign_software(payload.nonce)
        
        request.header = MessageHeaderType(self.session_parameters.session_id, int(time.time()))
        reaction = SendMessage()
        reaction.message = request
        extra_data = {}
        reaction.extra_data = extra_data
        reaction.msg_type = "IAM"
        return reaction
