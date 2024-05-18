"""
.. module:: process_service_selection_request
   :platform: Unix
   :synopsis: A module describing the ServiceSelection state.

.. Copyright 2022 EDF 

.. moduleauthor:: Oscar RODRIGUEZ INFANTE, Tony ZHOU, Trang PHAM, Efflam OLLIVIER 

.. License:: This source code is licensed under the MIT License.


"""

from .evse_state import EVSEState
from shared.reaction_message import ReactionToIncomingMessage, SendMessage
from shared.xml_classes.common_messages import ServiceSelectionRes, MessageHeaderType, ResponseCodeType
from shared.global_values import IAM_SERVICE_ID
from shared.log import logger
from tests.timer import validation_timer

import time


class ProcessServiceSelectionRequest(EVSEState):
    def __init__(self):
        super(ProcessServiceSelectionRequest, self).__init__(name="ProcessServiceSelectionReq")

    def process_payload(self, payload) -> ReactionToIncomingMessage:
        if (payload.selected_vaslist is not None):
            for service in payload.selected_vaslist.selected_service:
                # Deal with each VAS as necessary
                if (str(service.service_id) == IAM_SERVICE_ID):
                    self.controller.data_model.IAM_Module.configure(service.parameter_set_id)
        
        if self.controller.data_model.tpm_capability_challenge_accepted:
            validation_timer.resume()
            # Use the EVCC's MiMS list to calculate mutually supported mandatory services
            mutual_mandatory_service_ids = []
            if (self.controller.data_model.evcc_mandatory_if_mutually_supported_service_ids is not None):
                for service_id in self.controller.data_model.evcc_mandatory_if_mutually_supported_service_ids.service_id:
                    for service in self.controller.data_model.vaslist.service:
                        if service_id == service.service_id:
                            mutual_mandatory_service_ids.append(service_id)
            
            # Check all mutual mandatory services have been selected
            for service in payload.selected_vaslist.selected_service:
                if service.service_id in mutual_mandatory_service_ids:
                    mutual_mandatory_service_ids.remove(service_id)
            
            if mutual_mandatory_service_ids:
                # Mutually supported mandatory service not selected
                logger.warn("At least one mutually supported mandatory service was not enabled: " + str(mutual_mandatory_service_ids))
                response = ServiceSelectionRes()
                response.response_code = ResponseCodeType.FAILED
                response.header = MessageHeaderType(self.session_parameters.session_id, int(time.time()))
                reaction = SendMessage()
                extra_data = {}
                reaction.extra_data = extra_data
                reaction.message = response
                reaction.msg_type = "Common"
                return reaction
            
            vtime = validation_timer.stop()
            with open("secc_validation_time.txt", 'a') as f:
                f.write(str(vtime) + '\n')
        
        extra_data = {}
        response = ServiceSelectionRes()
        response.header = MessageHeaderType(self.session_parameters.session_id, int(time.time()))
        response.response_code = ResponseCodeType.OK  # TODO if service is accepted
        reaction = SendMessage()
        reaction.extra_data = extra_data
        reaction.message = response
        reaction.msg_type = "Common"
        return reaction
