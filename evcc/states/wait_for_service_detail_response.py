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
from shared.xml_classes.tpm import MessageHeaderType as TpmMessageHeaderType
from shared.global_values import IAM_SERVICE_ID, TPM_SERVICE_ID
from shared.log import logger
from shared.tpm import _parse_and_check_tpms_attest_cert
from tests.timer import validation_timer


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
            if str(payload.service_id) == TPM_SERVICE_ID and self.controller.data_model.tpm_capability_challenge_accepted:
                logger.debug("Received TPM Service Detail Request")
                #validation_timer.resume()
                # Combine the hashes of each service. Hash the result and check if it matches the TPM-signed hash.
                bytestring = bytearray()
                for parameter_set in sorted(payload.service_parameter_list.parameter_set, key = lambda p: int(p.parameter_set_id)):
                    for parameter in sorted(parameter_set.parameter, key = lambda p: int(p.name)):
                        logger.debug("Parameter: " + str(parameter.name) + " " + str(parameter.finite_string))
                        bytestring += bytearray(int(parameter.name).to_bytes(2, "big"))
                        bytestring += bytearray.fromhex(parameter.finite_string)
                print(bytestring.hex())
                calculated_hash = sha256(bytestring).hexdigest()
                logger.debug("Calculated hash: " + str(calculated_hash) + str(type(calculated_hash)))
                self.controller.data_model.tpm_calculated_hash = calculated_hash
                #evidence: bytes = self.controller.data_model.secc_tpm_evidence
                #logger.debug("Transmitted evidence: " +  str(evidence) + str(type(evidence)))
                
                #vtime = validation_timer.stop()
                #with open("evcc_validation_time.txt", 'a') as f:
                #    f.write(str(vtime) +'\n')
            # Create/append list of VASes to include in ServiceSelectionRequest
            if self.controller.data_model.selected_vaslist is None:
                self.controller.data_model.selected_vaslist = SelectedServiceListType([service])
            else:
                self.controller.data_model.selected_vaslist.selected_service.append(service)
        else: # Not a VAS, energy transfer service
            # Insert logic about whether we want this mode. For now assume yes
            self.controller.data_model.selected_energy_transfer_service = payload.service_id
                
        # If we have more services we want to detail (currently just VASes)
        extra_data = {}
        reaction = SendMessage()
        reaction.extra_data = extra_data
        if self.controller.data_model.vas_services_to_detail:
            request = ServiceDetailReq()
            request.service_id = self.controller.data_model.vas_services_to_detail[-1]
            reaction.msg_type = "Common"
            request.header = MessageHeaderType(self.session_parameters.session_id, int(time.time()))
        else: # we are moving on
            if self.controller.data_model.tpm_capability_challenge_accepted:
                request = CapabiltyEvidenceReq()
                reaction.msg_type = "TPM"
                request.header = TpmMessageHeaderType(self.session_parameters.session_id, int(time.time()))
            else:
                request = ServiceSelectionReq()
                # TODO: from the options in response, select one that is available
                request.selected_energy_transfer_service = SelectedServiceType(self.controller.data_model.selected_energy_transfer_service, 1)
                if self.controller.data_model.selected_vaslist: # Append selected VASes to packet, if we want any.
                    request.selected_vaslist = self.controller.data_model.selected_vaslist
                if self.controller.data_model.using_IAM is None:
                    self.controller.data_model.using_IAM = False
                request.header = MessageHeaderType(self.session_parameters.session_id, int(time.time()))
                reaction.msg_type = "Common"
                
                services = [service for service in self.controller.data_model.supported_service_ids.service_id]
                vases = [service for service in self.controller.data_model.supported_vas_service_ids.service_id]
                request.supported_service_ids = ServiceIdlistType(services + vases)
                request.mandatory_if_mutally_supported_service_ids = ServiceIdlistType([service for service in self.controller.data_model.mandatory_if_mutually_supported_service_ids.service_id])
                
                self.controller.data_model.quote_process.wait()
                request.challenge_evidence = self._get_tpm_evidence()
                request.challenge_signature = self._get_tpm_signature()
        
        reaction.message = request
        return reaction
    
    def _get_tpm_signature(self) -> bool:
        signature_der = open("../TPM/evcc/ecc_signature.der", 'rb').read()
        
        (r, s) = decode_dss_signature(signature_der)
        signature_p1363 = r.to_bytes(32, byteorder='big') + s.to_bytes(32, byteorder='big')
        return signature_p1363
    
    def _get_tpm_evidence(self) -> bool:
        return open("../TPM/evcc/attestation.nv_cert_info", 'rb').read()
