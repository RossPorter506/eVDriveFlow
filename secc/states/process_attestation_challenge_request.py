"""
.. module:: process_attestation_challenge_request
   :platform: Unix
   :synopsis: A module describing the AttestationChallenge state from IAM2.

.. Copyright 2022 EDF 

.. moduleauthor:: Ross PORTER

.. License:: This source code is licensed under the MIT License.


"""

from .evse_state import EVSEState
from shared.reaction_message import ReactionToIncomingMessage, SendMessage
from shared.xml_classes.common_messages import ResponseCodeType
from shared.xml_classes.iam import AttestationChallengeRes, MessageHeaderType
from shared.global_values import IAM_NONCE_SIZE
import time, os

from ecdsa import SigningKey
from tests.timer import attestation_timer

class ProcessAttestationChallengeRequest(EVSEState):
    def __init__(self):
        super(ProcessAttestationChallengeRequest, self).__init__(name="ProcessAttestationChallengeReq")

    def process_payload(self, payload) -> ReactionToIncomingMessage:
        # Technically we can begin attestation immediately, but the EVCC can only begin attesting *after* they recieve our message, and in this framework we 
        # can't do anything after sending our message. To get attestation happening in parallel we could spawn a thread, sleep for X ms (enough time for this thread to send our message), 
        # then begin attestation in the other thread, as we know the EVCC will also be busy attesting after they recieve our message.
        # There could be issues with missing packets while we're in the secure world, though ISO 15118-20 is built on TCP, so at worst it should require a retransmission if we miss the packet...
        # TODO: Implement and test async attestation
        attestation_timer.start()
        self.controller.attestation_info = hash_sign_software(payload.nonce.hex())
        atime = attestation_timer.stop()
        with open("../attestation.txt", 'a') as f:
            f.write(str(atime)+'\n')
        
        self.controller.challenge_nonce = os.urandom(IAM_NONCE_SIZE)
        extra_data = {}
        response = AttestationChallengeRes()
        attestation_timer.start()
        response.nonce = self.controller.challenge_nonce
        response.response_code = ResponseCodeType.OK
        response.header = MessageHeaderType(self.session_parameters.session_id, int(time.time()))
        reaction = SendMessage()
        reaction.extra_data = extra_data
        reaction.message = response
        reaction.msg_type = "IAM"
        return reaction
