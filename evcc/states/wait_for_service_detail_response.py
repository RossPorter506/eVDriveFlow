"""
.. module:: wait_for_service_detail_response
   :platform: Unix
   :synopsis: A module describing the ServiceDetail state.

.. Copyright 2022 EDF 

.. moduleauthor:: Oscar RODRIGUEZ INFANTE, Tony ZHOU, Trang PHAM, Efflam OLLIVIER 

.. License:: This source code is licensed under the MIT License.


"""

from evcc.states.ev_state import EVState
from shared.reaction_message import ReactionToIncomingMessage, SendMessage
from shared.xml_classes.common_messages import ServiceSelectionReq, ServiceDetailReq, MessageHeaderType, SelectedServiceType, SelectedServiceListType, SessionStopReq, ChargingSessionType
from shared.global_values import IAM_SERVICE_ID, TPM_SERVICE_ID
from shared.log import logger

import time

from hashlib import sha256

class WaitForServiceDetailResponse(EVState):
    def __init__(self):
        super(WaitForServiceDetailResponse, self).__init__(name="WaitForServiceDetailRes")

    def process_payload(self, payload) -> ReactionToIncomingMessage:
        # Did we ask about a VAS?
        if payload.service_id in self.controller.data_model.vas_services_to_detail:
            index = self.controller.data_model.vas_services_to_detail.index(payload.service_id)
            self.controller.data_model.vas_services_to_detail.pop(index)
            service = SelectedServiceType(payload.service_id, 1) # TODO: Define ParameterSetID
            
            if str(service.service_id) == IAM_SERVICE_ID:
                self.controller.data_model.using_IAM = True
            if str(payload.service_id) == TPM_SERVICE_ID:
                logger.debug("Received TPM Service Detail Request")
                bytestring = bytearray()
                for parameter_set in sorted(payload.service_parameter_list.parameter_set, key = lambda p: int(p.parameter_set_id)):
                    for parameter in sorted(parameter_set.parameter, key = lambda p: int(p.name)):
                        logger.debug("Parameter:", parameter.name, parameter.finite_string)
                        bytestring += bytearray(parameter.finite_string.encode("UTF-8"))
                calculated_hash = sha256(bytestring).hexdigest()
                logger.debug("Calculated hash:", calculated_hash, type(calculated_hash))
                logger.debug("Transmitted hash:", self.controller.data_model.secc_tpm_evidence, type(self.controller.data_model.secc_tpm_evidence))
                if calculated_hash != self.controller.data_model.secc_tpm_evidence:
                    logger.warn("Calculated hash does not match SECC's TPM-signed hash")
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

            # Create/append list of VASes to include in ServiceSelectionRequest
            if self.controller.data_model.selected_vaslist is None:
                self.controller.data_model.selected_vaslist = SelectedServiceListType(service)
            else:
                self.controller.data_model.selected_vaslist.append(service)
        else: # Not a VAS, energy transfer service
            # Insert logic about whether we want this mode. For now assume yes
            self.controller.data_model.selected_energy_transfer_service = payload.service_id
                
        # If we have more services we want to detail (currently just VASes)
        if self.controller.data_model.vas_services_to_detail:
            request = ServiceDetailReq()
            request.service_id = self.controller.data_model.vas_services_to_detail[-1]
        else: # we are moving on to service selection
            request = ServiceSelectionReq()
            # TODO: from the options in response, select one that is available
            request.selected_energy_transfer_service = SelectedServiceType(self.controller.data_model.selected_energy_transfer_service, 1)
            if self.controller.data_model.selected_vaslist: # Append selected VASes to packet, if we want any.
                request.selected_vaslist = self.controller.data_model.selected_vaslist
            if self.controller.data_model.using_IAM is None:
                self.controller.data_model.using_IAM = False

        request.header = MessageHeaderType(self.session_parameters.session_id, int(time.time()))
        extra_data = {}
        reaction = SendMessage()
        reaction.extra_data = extra_data
        reaction.message = request
        reaction.msg_type = "Common"
        return reaction
