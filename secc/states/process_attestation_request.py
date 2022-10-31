"""
.. module:: process_service_detail_request
   :platform: Unix
   :synopsis: A module describing the ServiceDetail state.

.. Copyright 2022 EDF 

.. moduleauthor:: Oscar RODRIGUEZ INFANTE, Tony ZHOU, Trang PHAM, Efflam OLLIVIER 

.. License:: This source code is licensed under the MIT License.


"""

from secc.states.evse_state import EVSEState
from shared.reaction_message import ReactionToIncomingMessage, SendMessage
from shared.xml_classes.common_messages import ResponseCodeType
from shared.xml_classes.iam import AttestationRes, MessageHeaderType
import time
from ecdsa import SigningKey

EVIDENCE_SIZE_BYTES = 40

class ProcessAttestationRequest(EVSEState):
    def __init__(self):
        super(ProcessAttestationRequest, self).__init__(name="ProcessAttestationReq")
        with open("../shared/certificates/IAM_keys/secc_secure_key.pem", "r") as secure_key_file:
            self.secc_secure_key = SigningKey.from_pem(secure_key_file.read())

    def process_payload(self, payload) -> ReactionToIncomingMessage:
        extra_data = {}
        response = AttestationRes()
        response.evidence = int(1).to_bytes(EVIDENCE_SIZE_BYTES, "big") #TODO: placeholder
        response.signature = self.secc_secure_key.sign_deterministic(response.evidence)
        response.response_code = ResponseCodeType.OK
        response.header = MessageHeaderType(self.session_parameters.session_id, int(time.time()))
        reaction = SendMessage()
        reaction.extra_data = extra_data
        reaction.message = response
        reaction.msg_type = "IAM"
        return reaction
