package com.webank.wedpr.crypto.zkp;

public class NativeInterface {
    static {
        String libraryPath = ZkpDemo.class.getResource("/lib/libffi_java_zkp.dylib").getPath();
        System.load(libraryPath);
//        System.loadLibrary("ffi_java_zkp");
    }

    public native ZkpResult proveKnowledgeProof(int value, byte[] blinding);

    public native ZkpResult verifyKnowledgeProof(byte[] commitment, byte[] proof);

    public native ZkpResult proveValueEqualityRelationshipProof(int value1, byte[] blinding1);

    public native ZkpResult verifyValueEqualityRelationshipProof(int value1, byte[] commitment1, byte[] proof);

    public native ZkpResult senderProveMultiSumRelationshipSetup(int values, byte[] blindings);

    public native ZkpResult senderProveMultiSumRelationshipFinal(int values, byte[] blindings, byte[] proofSecret, byte[] check);

    public native ZkpResult receiverProveMultiSumRelationshipSetup(int values, byte[] blindings);

    public native ZkpResult receiverProveMultiSumRelationshipFinal(byte[] blindings, byte[] proofSecret, byte[] check);

    public native ZkpResult coordinatorProveMultiSumRelationshipSetup(byte[] senderSetupLists, byte[] receiverSetupLists);

    public native ZkpResult coordinatorProveMultiSumRelationshipFinal(byte[] check, byte[] senderProofs, byte[] receiverProofs);

    public native ZkpResult verifyMultiSumRelationship(byte[] inputCommitments, byte[] outputCommitments, byte[] proof);

    public native ZkpResult proveRangeProof(int value, byte[] blinding);

    public native ZkpResult verifyRangeProof(byte[] commitment, byte[] proof);

    public native ZkpResult computeCommitment(int value, byte[] blinding);

    public native ZkpResult computeViewkey(byte[] blinding);
}
