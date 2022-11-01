"""
.. module:: wait_for_attestation_response
   :platform: Unix
   :synopsis: A module describing the Attestation state (for IAM).

.. Copyright 2022 EDF 

.. moduleauthor:: Ross PORTER

.. License:: This source code is licensed under the MIT License.


"""

from evcc.states.ev_state import DcEVState
from shared.reaction_message import ReactionToIncomingMessage, SendMessage
import time
from shared.xml_classes.common_messages import ScheduleExchangeReq, SessionStopReq, MessageHeaderType, ChargingSessionType
from shared.log import logger

from ecdsa import VerifyingKey, BadSignatureError

class WaitForAttestationResponse(DcEVState):
    def __init__(self):
        super(WaitForAttestationResponse, self).__init__(name="WaitForAttestationRes")
        with open("../shared/certificates/IAM_keys/secc_public_attestation_key.pem", "r") as pub_key_file:
            self.secc_public_key = VerifyingKey.from_pem(pub_key_file.read())
        with open("../IAM/secc.sha256", "rb") as f:
            self.expected_hash = f.read()

    def process_payload(self, payload) -> ReactionToIncomingMessage:
        if payload.evidence and payload.signature \
            and self._verify(payload.evidence, payload.signature): #attestation success, continue to schedule exchange
            logger.info('Attestation Successful. Continuing session.')

            request = ScheduleExchangeReq()
            request.maximum_supporting_points = 1024
            request.dynamic_sereq_control_mode = self.controller.data_model.get_dynamic_sereq_control_mode()
        else: # attestation failed - SECC possibly compromised
            logger.warn('Attestation Failed. Ending session.')
            self.controller.stop() # Signal rest of system to wind down
            request = SessionStopReq()
            request.charging_session = ChargingSessionType.TERMINATE

            # message vague on purpose. We probably shouldn't mention attestation at all.
            request.evtermination_code = "Attestation Failure"
            request.evtermination_explanation = "Failure during attestation" 
        
        extra_data = {}
        request.header = MessageHeaderType(self.session_parameters.session_id, int(time.time()))
        reaction = SendMessage()
        reaction.message = request
        reaction.extra_data = extra_data
        reaction.msg_type = "Common"
        return reaction

    def _verify(self, hsh: bytes, sig: bytes) -> bool:
        try:
            signature_correct = self.secc_public_key.verify(sig, self.controller.data_model.challenge_nonce + hsh)
        except BadSignatureError:
            signature_correct = False

        hash_correct = (hsh == self.expected_hash)

        return all([signature_correct, hash_correct])
    