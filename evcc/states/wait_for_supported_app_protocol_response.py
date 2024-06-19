"""
.. module:: wait_for_supported_app_protocol_response
   :platform: Unix
   :synopsis: A module describing the SupportedAppProtocol state.

.. Copyright 2022 EDF 

.. moduleauthor:: Oscar RODRIGUEZ INFANTE, Tony ZHOU, Trang PHAM, Efflam OLLIVIER, Ross PORTER

.. License:: This source code is licensed under the MIT License.


"""

from shared.log import logger
from shared.reaction_message import ReactionToIncomingMessage, SendMessage
from evcc.states.ev_state import EVState
from shared.xml_classes.common_messages import SessionSetupReq, MessageHeaderType
from shared.xml_classes.app_protocol import ResponseCodeType
from shared.xml_classes.tpm import CapabilityChallengeReq, ServiceIdlistType
from shared.xml_classes.tpm import MessageHeaderType as TpmMessageHeaderType
from shared.global_values import CAPABILITY_NONCE_SIZE, TPM_SCHEMA_ID

import time, os


class WaitForSupportedAppProtocolResponse(EVState):
    def __init__(self):
        super(WaitForSupportedAppProtocolResponse, self).__init__(name="WaitForSupportedAppProtocolRes")

    def process_payload(self, payload) -> ReactionToIncomingMessage:
        extra_data = {}
        # Saving session id
        session_id = "00000000".encode("ascii")
        extra_data["session_id"] = session_id
        match = False
        if payload.response_code == ResponseCodeType.OK_SUCCESSFUL_NEGOTIATION or \
                payload.response_code == ResponseCodeType.OK_SUCCESSFUL_NEGOTIATION_WITH_MINOR_DEVIATION:
            logger.info("Successful negotiation.")
            for app_protocol in self.session_parameters.supported_app_protocols:
                if app_protocol.schema_id == payload.schema_id:
                    extra_data['chosen_app_protocol'] = app_protocol
            match = True
        
        reaction = SendMessage()
        if payload.schema_id == TPM_SCHEMA_ID:
            logger.info("TPM begins.")
            self.controller.data_model.tpm_capability_challenge_accepted = True
            request = CapabilityChallengeReq()
            
            self.controller.data_model.secc_challenge_nonce = os.urandom(CAPABILITY_NONCE_SIZE)
            request.challenge_nonce = self.controller.data_model.secc_challenge_nonce
            
            reaction.msg_type = "TPM"
            request.header = TpmMessageHeaderType(session_id, int(time.time()))
        else:
            logger.info("Normal begins.")
            request = SessionSetupReq()
            reaction.msg_type = "Common"
            request.header = MessageHeaderType(session_id, int(time.time()))
            if match:
                request.evccid = self.controller.data_model.evccid
        
        reaction.message = request
        reaction.extra_data = extra_data
        return reaction
