/*
 * Copyright 2020. Huawei Technologies Co., Ltd. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */

package com.sample.authenticator.server;

import com.sample.authenticator.server.param.ServerAssertionResultRequest;
import com.sample.authenticator.server.param.ServerAttestationResultRequest;
import com.sample.authenticator.server.param.ServerPublicKeyCredentialCreationOptionsRequest;
import com.sample.authenticator.server.param.ServerPublicKeyCredentialCreationOptionsResponse;
import com.sample.authenticator.server.param.ServerRegDeleteRequest;
import com.sample.authenticator.server.param.ServerRegInfoRequest;
import com.sample.authenticator.server.param.ServerRegInfoResponse;
import com.sample.authenticator.server.param.ServerResponse;


public interface IFidoServer {
    ServerPublicKeyCredentialCreationOptionsResponse
        getAttestationOptions(ServerPublicKeyCredentialCreationOptionsRequest request);

    ServerResponse getAttestationResult(ServerAttestationResultRequest attestationResultRequest);

    ServerPublicKeyCredentialCreationOptionsResponse getAssertionOptions(
        ServerPublicKeyCredentialCreationOptionsRequest serverPublicKeyCredentialCreationOptionsRequest);

    ServerResponse getAssertionResult(ServerAssertionResultRequest assertionResultRequest);

    ServerRegInfoResponse getRegInfo(ServerRegInfoRequest regInfoRequest);

    ServerResponse delete(ServerRegDeleteRequest regDeleteRequest);
}
