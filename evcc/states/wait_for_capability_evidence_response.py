"""
.. module:: wait_for_capability_evidence_response
   :platform: Unix
   :synopsis: A module describing the EVCC Capability Challenge state.

.. Copyright 2022 EDF 

.. moduleauthor:: Ross PORTER

.. License:: This source code is licensed under the MIT License.


"""

from evcc.states.ev_state import DcEVState
from shared.reaction_message import ReactionToIncomingMessage, SendMessage
from shared.xml_classes.common_messages import SessionStopReq, MessageHeaderType, ChargingSessionType, SessionSetupReq
from shared.xml_classes.tpm import ResponseCodeType
from shared.log import logger

import time
from ecdsa import VerifyingKey, BadSignatureError

class WaitForCapabilityEvidenceResponse(DcEVState):
    def __init__(self):
        super(WaitForCapabilityEvidenceResponse, self).__init__(name="WaitForCapabilityEvidenceRes")

    def process_payload(self, payload) -> ReactionToIncomingMessage:
        reaction = SendMessage()
        if payload.response_code == ResponseCodeType.OK:
            # SECC was happy with our evidence
            logger.info('EVCC Capability Evidence Accepted.')
            
            # TPM quote untampered
            evidence_ok = self._verify(payload.challenge_signature, payload.challenge_evidence, self.controller.data_model.secc_challenge_nonce):
            
            # Calculated service hash matches hash in TPM quote
            services_ok = _parse_and_check_tpms_attest_cert(payload.challenge_evidence, self.controller.data_model.secc_challenge_nonce, self.controller.data_model.tpm_calculated_hash)
            
            if not (evidence_ok and services_ok):
                if not evidence_ok:
                    logger.warn("Error during parsing TPMS_ATTEST cert: Quote failed verification")
                if not service_ok:
                    logger.warn('Calculated service hash does not match hash from TPM quote. Ending session.')
                
                self.controller.stop()
                request = SessionStopReq()
                request.charging_session = ChargingSessionType.TERMINATE
                # We probably shouldn't mention attestation at all.
                request.evtermination_code = "SECC capability attestation failure"
                request.evtermination_explanation = "Failure during SECC capability attestation"
                request.header = MessageHeaderType(self.session_parameters.session_id, int(time.time()))
                reaction = SendMessage()
                reaction.extra_data = {}
                reaction.message = request
                reaction.msg_type = "Common"
                return reaction
            
            logger.info('SECC Capability Attestation Successful. Continuing to Service Selection')
            request = ServiceSelectionReq()
            request.selected_energy_transfer_service = SelectedServiceType(self.controller.data_model.selected_energy_transfer_service, 1)
            if self.controller.data_model.selected_vaslist: # Append selected VASes to packet, if we want any.
                request.selected_vaslist = self.controller.data_model.selected_vaslist
            if self.controller.data_model.using_IAM is None:
                self.controller.data_model.using_IAM = False
            request.header = MessageHeaderType(session_id, int(time.time()))
        else: # attestation failed - EVCC possibly compromised
            logger.warn('EVCC capability attestation failed. Ending session.')
            self.controller.stop() # Signal rest of system to wind down
            request = SessionStopReq()
            request.charging_session = ChargingSessionType.TERMINATE
            # message vague on purpose. We probably shouldn't mention attestation at all.
            request.evtermination_code = "SECC capability attestation failure"
            request.evtermination_explanation = "Failure during SECC capability attestation"
        
        request.header = MessageHeaderType(self.session_parameters.session_id, int(time.time()))
        reaction.msg_type = "Common"
        reaction.message = request
        extra_data = {}
        reaction.extra_data = extra_data
        return reaction
    
    def _verify(self, sig: bytes, message: bytes, nonce: bytes) -> bool:
        r = int.from_bytes(sig[0:32], "big")
        s = int.from_bytes(sig[32:64], "big")
        sig_der = encode_dss_signature(int(r), int(s))
        
        open("sig_file", 'wb').write(sig_der)
        open("message_file", 'wb').write(message)
        
        try:
            subprocess.check_output(["tpm2_checkquote", \
                "-u", "../TPM/secc/secc_sign_public_key.pem", \
                "-g", "sha256", \
                "-m", "message_file", \
                "-s", "sig_file", \
                "-q", nonce.hex()])
        except subprocess.CalledProcessError as e:
            logger.warn("Signature verification failed:" + str(e))
            return False
        
        return True
