"""
.. module:: wait_for_capability_attestation_secc_response
   :platform: Unix
   :synopsis: A module describing the SECC Capability Challenge state.

.. Copyright 2022 EDF 

.. moduleauthor:: Ross PORTER

.. License:: This source code is licensed under the MIT License.


"""

from evcc.states.ev_state import DcEVState
from shared.reaction_message import ReactionToIncomingMessage, SendMessage
import time
from shared.xml_classes.common_messages import SessionStopReq, MessageHeaderType, ChargingSessionType
from shared.xml_classes.tpm import SeccCapabilityChallengeReq
from shared.xml_classes.tpm import MessageHeaderType as TpmMessageHeaderType
from shared.log import logger

from ecdsa import VerifyingKey, BadSignatureError

class WaitForSeccCapabilityChallengeResponse(DcEVState):
    def __init__(self):
        super(WaitForSeccCapabilityChallengeResponse, self).__init__(name="WaitForSeccCapabilityChallengeRes")

    def process_payload(self, payload) -> ReactionToIncomingMessage:
        reaction = SendMessage()
        if payload.evidence and payload.signature \
            and self._verify(payload.evidence, payload.signature):
            # Hash matches sig. We don't know if hash is good until we can inspect the services during ServiceDetail. Continue for now.
            logger.info('SECC Capability Attestation Successful so far. Continuing to EVCC capability attestation.')
            request = EvccCapabilityChallengeReq()
            request.header = TpmMessageHeaderType(self.session_parameters.session_id, int(time.time()))
            reaction.msg_type = "TPM"

        else: # attestation failed - SECC possibly compromised
            logger.warn('SECC capability attestation failed. Ending session.')
            self.controller.stop() # Signal rest of system to wind down
            request = SessionStopReq()
            request.charging_session = ChargingSessionType.TERMINATE
            # message vague on purpose. We probably shouldn't mention attestation at all.
            request.evtermination_code = "SECC capability attestation failure"
            request.evtermination_explanation = "Failure during SECC capability attestation"
            reaction.msg_type = "Common"
            request.header = MessageHeaderType(self.session_parameters.session_id, int(time.time()))
        
        reaction.message = request
        extra_data = {}
        reaction.extra_data = extra_data
        return reaction

    def _verify(self, hsh: bytes, sig: bytes) -> bool: # TODO
        logger.warn('TODO Verifier used')
        return True
        #try:
        #    signature_correct = self.secc_public_key.verify(sig, self.controller.data_model.challenge_nonce + hsh)
        #except BadSignatureError:
        #    signature_correct = False

        #hash_correct = (hsh == self.expected_hash)

        #return all([signature_correct, hash_correct])
    
