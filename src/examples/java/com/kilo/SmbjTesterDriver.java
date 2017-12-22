/*
 * Copyright (C)2016 - SMBJ Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.kilo;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.EnumSet;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.msfscc.fileinformation.FileIdBothDirectoryInformation;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2CreateOptions;
import com.hierynomus.mssmb2.SMB2ShareAccess;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.auth.PlatformGSSAuthenticationContext;
import com.hierynomus.smbj.auth.PlatformGSSAuthenticator;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.File;

public class SmbjTesterDriver {

    private static String URL = "";
    private static String SHARE = "";
    private static String FOLDER = "";

    static {
        System.setProperty("sun.security.jgss.native", "true");
        System.setProperty("sun.security.jgss.lib", "/usr/libexec/libgsswrap.so");
        System.setProperty("sun.security.jgss.nativegss.debug", "true");
        System.setProperty("sun.security.jgss.debug", "true");
    }

    public static void main(String args[]) throws Exception {
        if(args.length != 3) {
            System.out.println(args.length);
            help();
            return;
        }
        URL = args[0];
        SHARE = args[1];
        FOLDER = args[2];

        SmbConfig config = SmbConfig.builder().withAuthenticators(new PlatformGSSAuthenticator.Factory()).build();
        SMBClient client = new SMBClient(config);

        try (Connection connection = client.connect(URL)) {
            AuthenticationContext ac = new PlatformGSSAuthenticationContext();
            Session session = connection.authenticate(ac);
            // Connect to Share
            try (DiskShare share = (DiskShare) session.connectShare(SHARE)) {
                for (FileIdBothDirectoryInformation f : share.list(FOLDER, "*")) {
                    System.out.println("File : " + f.getFileName());
                    if(f.getFileName().equalsIgnoreCase("test")) {
                        File file = share.openFile(FOLDER+"/"+f.getFileName(), EnumSet.of(AccessMask.GENERIC_READ), EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL),
                            EnumSet.of(SMB2ShareAccess.FILE_SHARE_READ),
                            SMB2CreateDisposition.FILE_OPEN, EnumSet.noneOf(SMB2CreateOptions.class));
                        StringBuilder result = new StringBuilder();
                        String line;
                        boolean flag = false;
                        String newLine = System.getProperty("line.separator");
                        BufferedReader reader = new BufferedReader(new InputStreamReader(file.getInputStream()));
                        while ((line = reader.readLine()) != null) {
                            result.append(flag? newLine: "").append(line);
                            flag = true;
                        }
                        System.out.println("File contents -->" + result.toString());
                    }
                }
            }
        }
    }

    private static void help(){
        System.out.println("Add arguments in the order of:");
        System.out.println("[host] [share] [directory]");
    }
}
