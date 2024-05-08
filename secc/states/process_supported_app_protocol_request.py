"""
.. module:: process_supported_app_protocol_request
   :platform: Unix
   :synopsis: A module describing the SupportedAppProtocol state.

.. Copyright 2022 EDF 

.. moduleauthor:: Oscar RODRIGUEZ INFANTE, Tony ZHOU, Trang PHAM, Efflam OLLIVIER, Ross PORTER

.. License:: This source code is licensed under the MIT License.


"""


from shared.reaction_message import ReactionToIncomingMessage, SendMessage
from .evse_state import EVSEState
from shared.xml_classes.app_protocol import SupportedAppProtocolReq, SupportedAppProtocolRes, ResponseCodeType
from tests.timer import handshake_timer

class ProcessSupportedAppProtocolRequest(EVSEState):
    def __init__(self):
        super(ProcessSupportedAppProtocolRequest, self).__init__(name="ProcessSupportedAppProtocolReq")

    def process_payload(self, payload) -> ReactionToIncomingMessage:
        handshake_timer.start()
        match = False
        extra_data = {}
        response_code = ResponseCodeType.FAILED_NO_NEGOTIATION
        response = SupportedAppProtocolRes()
        self.controller.data_model.tpm_capability_challenge_accepted = False
        
        if isinstance(payload, SupportedAppProtocolReq):
            # Sorting app protocols by priority
            payload.app_protocol.sort(key=self.get_priority)
            
            # If we see Modified 15118-20, set flag and continue normally for now
            for protocol in payload.app_protocol:
                if protocol.protocol_namespace == V2G_CI_MSG_TPM_NAMESPACE:
                    self.controller.data_model.tpm_capability_challenge_accepted = True
                    break
            
            for protocol in payload.app_protocol:
                if protocol.protocol_namespace == V2G_CI_MSG_TPM_NAMESPACE: # don't bother checking this version for now
                    continue
                for supported_protocol in self.get_supported_app_protocols():
                    if protocol.protocol_namespace == supported_protocol.protocol_namespace and \
                            protocol.version_number_major == supported_protocol.version_number_major:
                        if protocol.version_number_minor == supported_protocol.version_number_minor:
                            response_code = ResponseCodeType.OK_SUCCESSFUL_NEGOTIATION
                        else:
                            response_code = ResponseCodeType.OK_SUCCESSFUL_NEGOTIATION_WITH_MINOR_DEVIATION
                        match = True
                        response.schema_id = protocol.schema_id
                        # Saving schema id in session
                        extra_data['schema_id'] = protocol.schema_id
                        self.controller.data_model.chosen_schema_id = protocol.schema_id
                        break
                if match:
                    break
        response.response_code = response_code
        reaction = SendMessage()
        reaction.message = response
        reaction.extra_data = extra_data
        reaction.msg_type = "SupportedAppProtocol"
        return reaction

    @staticmethod
    def get_priority(app_protocol):
        return app_protocol.priority

    def get_supported_app_protocols(self):
        return self.controller.data_model.supported_app_protocols
