"""
.. module:: process_attestation_evidence_request
   :platform: Unix
   :synopsis: A module describing the AttestationEvidence state from IAM2.

.. Copyright 2022 EDF 

.. moduleauthor:: Ross PORTER

.. License:: This source code is licensed under the MIT License.


"""

from .evse_state import EVSEState
from shared.reaction_message import ReactionToIncomingMessage, SendMessage
from shared.xml_classes.common_messages import ResponseCodeType
from shared.xml_classes.iam import AttestationEvidenceRes, MessageHeaderType
import time

from ecdsa import SigningKey
from IAM.IAM_TEE import hash_sign_software

class ProcessAttestationEvidenceRequest(EVSEState):
    def __init__(self):
        super(ProcessAttestationEvidenceRequest, self).__init__(name="ProcessAttestationEvidenceReq")
        with open("../shared/certificates/IAM_keys/evcc_public_attestation_key.pem", "r") as pub_key_file:
            self.secc_public_key = VerifyingKey.from_pem(pub_key_file.read())
        with open("../IAM/evcc.sha256", "rb") as f:
            self.expected_hash = f.read()

    def process_payload(self, payload) -> ReactionToIncomingMessage:
        # TODO: Verify EVCC evidence
        extra_data = {}
        response = AttestationEvidenceRes()
        (response.evidence, response.signature) = self.controller.attestation_info
        
        if payload.evidence and payload.signature \
            and self._verify(payload.evidence, payload.signature): #attestation success, continue to schedule exchange
            response.response_code = ResponseCodeType.OK
            logger.info('EVCC succeeded attestation')
        else: # EVCC evidence rejected
            response.response_code = ResponseCodeType.FAILED
            logger.warn('EVCC failed attestation')
        
        response.header = MessageHeaderType(self.session_parameters.session_id, int(time.time()))
        reaction = SendMessage()
        reaction.extra_data = extra_data
        reaction.message = response
        reaction.msg_type = "IAM"
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
