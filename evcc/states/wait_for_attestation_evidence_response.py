"""
.. module:: wait_for_attestation_evidence_response
   :platform: Unix
   :synopsis: A module describing the AttestationEvidence state (for IAM2).

.. Copyright 2022 EDF 

.. moduleauthor:: Ross PORTER

.. License:: This source code is licensed under the MIT License.


"""

from evcc.states.ev_state import DcEVState
from shared.reaction_message import ReactionToIncomingMessage, SendMessage
import time
from shared.xml_classes.common_messages import ScheduleExchangeReq, SessionStopReq, MessageHeaderType, ChargingSessionType, ResponseCodeType
from shared.log import logger
from shared.xml_classes.dc import DcChargeParameterDiscoveryReq, MessageHeaderType as MessageHeaderTypeDC


from ecdsa import VerifyingKey, BadSignatureError

class WaitForAttestationEvidenceResponse(DcEVState):
    def __init__(self):
        super(WaitForAttestationEvidenceResponse, self).__init__(name="WaitForAttestationEvidenceRes")
        with open("../shared/certificates/IAM_keys/secc_public_attestation_key.pem", "r") as pub_key_file:
            self.secc_public_key = VerifyingKey.from_pem(pub_key_file.read())
        with open("../IAM/secc.sha256", "rb") as f:
            self.expected_hash = f.read()

    def process_payload(self, payload) -> ReactionToIncomingMessage:
        if payload.response_code == ResponseCodeType.FAILED: # EVCC attestation failed.
            self.controller.stop() # Signal rest of system to wind down
            request = SessionStopReq()
            request.charging_session = ChargingSessionType.TERMINATE
            # message vague on purpose. We probably shouldn't mention attestation at all.
            request.evtermination_code = "Attestation Failure"
            request.evtermination_explanation = "Failure during attestation" 
            request.header = MessageHeaderType(self.session_parameters.session_id, int(time.time()))
            reaction = SendMessage()
            reaction.msg_type = "Common"
            reaction.message = request
            extra_data = {}
            reaction.extra_data = extra_data
            return reaction
        
        logger.debug('Evidence and signature present: %s, %s', bool(payload.evidence), bool(payload.signature))
        if payload.evidence and payload.signature \
            and self._verify(payload.evidence, payload.signature): #attestation success, continue to schedule exchange
            logger.info('Attestation Successful. Continuing session.')
            
            request = DcChargeParameterDiscoveryReq()
            request.header = MessageHeaderTypeDC(self.session_parameters.session_id, int(time.time()))
            # TODO: test based on service selected
            request.bpt_dc_cpdreq_energy_transfer_mode = self.controller.data_model.get_bpt_dc_cpdreq_energy_transfer_mode()
            reaction = SendMessage()
            reaction.msg_type = "DC"
        else: # attestation failed - SECC possibly compromised
            logger.warn('Attestation Failed. Ending session.')
            self.controller.stop() # Signal rest of system to wind down
            request = SessionStopReq()
            request.charging_session = ChargingSessionType.TERMINATE
            
            # message vague on purpose. We probably shouldn't mention attestation at all.
            request.evtermination_code = "Attestation Failure"
            request.evtermination_explanation = "Failure during attestation" 
            
            request.header = MessageHeaderType(self.session_parameters.session_id, int(time.time()))
            reaction = SendMessage()
            reaction.msg_type = "Common"
        
        reaction.message = request
        extra_data = {}
        reaction.extra_data = extra_data
        return reaction

    def _verify(self, hsh: bytes, sig: bytes) -> bool:
        try:
            signature_correct = self.secc_public_key.verify(sig, self.controller.data_model.challenge_nonce + hsh)
            logger.debug('Signature well-formed')
        except BadSignatureError:
            logger.debug('Signature malformed')
            signature_correct = False

        hash_correct = (hsh == self.expected_hash)

        logger.debug('Signature correct: %s, Hash correct: %s', signature_correct, hash_correct)
        return (signature_correct and hash_correct)
    
