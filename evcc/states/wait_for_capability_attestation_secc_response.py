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
from shared.xml_classes.tpm import SeccCapabilityChallengeReq, EvccCapabilityChallengeReq
from shared.xml_classes.tpm import MessageHeaderType as TpmMessageHeaderType
from shared.log import logger

import os

from hashlib import sha256
from ecdsa import VerifyingKey, BadSignatureError

class WaitForSeccCapabilityChallengeResponse(DcEVState):
    def __init__(self):
        super(WaitForSeccCapabilityChallengeResponse, self).__init__(name="WaitForSeccCapabilityChallengeRes")
        #with open("../shared/certificates/TPM_keys/secc_public_attestation_key.pem", "r") as pub_key_file:
        #    self.secc_public_key = VerifyingKey.from_pem(pub_key_file.read())

    def process_payload(self, payload) -> ReactionToIncomingMessage:
        reaction = SendMessage()
        if payload.challenge_evidence and payload.challenge_signature \
        and self._verify(payload.challenge_evidence, payload.challenge_signature):
            # Hash matches sig. We don't know if hash is good until we can inspect the services during ServiceDetail. Continue for now.
            self.controller.data_model.secc_tpm_evidence = payload.challenge_evidence.hex()
            logger.info('SECC Capability Attestation Successful so far. Continuing to EVCC capability attestation.')
            request = EvccCapabilityChallengeReq()
            request.challenge_evidence = self._get_tpm_evidence()
            request.challenge_signature = self._get_tpm_signature(payload.challenge_nonce)
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

    def _verify(self, hsh: bytes, sig: bytes) -> bool:
        logger.warn('Stubbed verifier used.')
        return True
        
        #try:
        #    return self.secc_public_key.verify(sig, self.controller.data_model.challenge_nonce + hsh)
        #except BadSignatureError:
        #    return False

    def _get_tpm_signature(self, nonce: bytes) -> bool:
        logger.warn('Stubbed TPM signature used.')
        return os.urandom(64)

    def _get_tpm_evidence(self) -> bool:
        logger.warn('Stubbed TPM evidence used.')
        return sha256(bytes(0)).hexdigest()
