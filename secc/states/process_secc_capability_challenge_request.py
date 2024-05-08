"""
.. module:: process_secc_capability_challenge_request
   :platform: Unix
   :synopsis: A module describing the SECC Capability Challenge state.

.. Copyright 2022 EDF 

.. moduleauthor:: Ross PORTER

.. License:: This source code is licensed under the MIT License.


"""

from .evse_state import EVSEState
from shared.reaction_message import ReactionToIncomingMessage, SendMessage
from shared.xml_classes.common_messages import ResponseCodeType
from shared.xml_classes.tpm import SeccCapabilityChallengeRes, MessageHeaderType
from shared.global_values import CAPABILITY_NONCE_SIZE

import time

from ecdsa import SigningKey
from tests.timer import attestation_timer

class ProcessSeccCapabilityChallengeRequest(EVSEState):
    def __init__(self):
        super(ProcessSeccCapabilityChallengeRequest, self).__init__(name="ProcessSeccCapabilityChallengeReq")

    def process_payload(self, payload) -> ReactionToIncomingMessage:
        
        extra_data = {}
        response = SeccCapabilityChallengeRes()
        #attestation_timer.start()
        #(response.evidence, response.signature) = hash_sign_secc_software(payload.challenge_nonce.hex())
        response.challenge_evidence = self._get_tpm_cert(nonce)
        response.challenge_nonce = os.urandom(CAPABILITY_NONCE_SIZE)
        #atime = attestation_timer.stop()
        #with open("../attestation.txt", 'a') as f:
        #    f.write(str(atime)+'\n')
        response.response_code = ResponseCodeType.OK
        response.header = MessageHeaderType(self.session_parameters.session_id, int(time.time()))
        reaction = SendMessage()
        reaction.extra_data = extra_data
        reaction.message = response
        reaction.msg_type = "TPM"
        return reaction
    
    def _get_tpm_cert(nonce: bytes):
        return None #TODO
