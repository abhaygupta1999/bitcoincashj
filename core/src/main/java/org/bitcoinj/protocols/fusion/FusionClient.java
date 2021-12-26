package org.bitcoinj.protocols.fusion;

import com.google.protobuf.ByteString;
import fusion.Fusion;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.bitcoinj.core.*;
import org.bitcoinj.crypto.Pedersen;
import org.bitcoinj.crypto.SchnorrBlindSignatureRequest;
import org.bitcoinj.protocols.fusion.models.Component;
import org.bitcoinj.protocols.fusion.models.GeneratedComponents;
import org.bitcoinj.protocols.fusion.models.Tier;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.wallet.Wallet;
import org.bouncycastle.util.encoders.Hex;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.*;

public class FusionClient {
    private final int STANDARD_TIMEOUT = 3;
    private final int WARMUP_SLOP = 3;
    private final long MIN_OUTPUT = 10000;
    private final long MAX_CLOCK_DISCREPANCY = 5;
    private final long MAX_EXCESS_FEE = 10000;
    private final long MAX_COMPONENTS = 40;
    private final long MIN_TX_COMPONENTS = 11;
    private SSLSocket socket;
    private String host;
    private int port;
    private BufferedOutputStream out;
    private BufferedInputStream in;
    private byte[] magicBytes;
    private Wallet wallet;
    private Pedersen pedersen;

    private ArrayList<Pair<TransactionOutput, ECKey>> coins = new ArrayList<>();
    private ArrayList<Pair<TransactionOutput, ECKey>> inputs = new ArrayList<>();
    private HashMap<Long, ArrayList<Long>> tierOutputs = new HashMap<>();
    private ArrayList<Pair<Script, Long>> outputs = new ArrayList<>();

    private long numComponents;
    private long componentFeeRate;
    private long minExcessFee;
    private long maxExcessFee;
    private ArrayList<Tier> availableTiers;
    private long tier;

    public FusionClient(String host, int port, ArrayList<TransactionOutput> coins, NetworkParameters params, Wallet wallet) throws IOException {
        SSLSocketFactory factory = (SSLSocketFactory)SSLSocketFactory.getDefault();
        SSLSocket socket = (SSLSocket)factory.createSocket(host, port);
        socket.setTcpNoDelay(true);
        socket.setKeepAlive(true);
        socket.setUseClientMode(true);
        socket.startHandshake();
        this.pedersen = new Pedersen(Hex.decode("0243617368467573696f6e2067697665732075732066756e676962696c6974792e"));
        this.socket = socket;
        this.wallet = wallet;
        for(TransactionOutput coin : coins) {
            ECKey key = this.wallet.findKeyFromAddress(coin.getAddressFromP2PKHScript(params));
            this.coins.add(Pair.of(coin, key));
        }
        this.availableTiers = new ArrayList<>();
        this.magicBytes = Hex.decode("765be8b4e4396dcf");
        this.host = host;
        this.port = port;
        out = new BufferedOutputStream(socket.getOutputStream());
        in = new BufferedInputStream(socket.getInputStream());

        greet();
    }

    public void sendMessage(Fusion.ClientMessage clientMessage) throws IOException {
        int size = clientMessage.toByteArray().length;

        UnsafeByteArrayOutputStream bos = new UnsafeByteArrayOutputStream();
        bos.write(magicBytes);

        ByteBuffer sizeBuf = ByteBuffer.allocate(4);
        sizeBuf.putInt(size);
        bos.write(sizeBuf.array());

        bos.write(clientMessage.toByteArray());
        out.write(bos.toByteArray());
        out.flush();

        System.out.println("sent: " + Hex.toHexString(bos.toByteArray()));
    }

    public Fusion.ServerMessage receiveMessage(int timeout) throws IOException {
        this.socket.setSoTimeout(timeout);
        byte[] prefixBytes = in.readNBytes(12);
        if(prefixBytes.length == 0) return null;
        byte[] sizeBytes = Arrays.copyOfRange(prefixBytes, 8, 12);
        int bufferSize = new BigInteger(sizeBytes).intValue();
        return Fusion.ServerMessage.parseFrom(in.readNBytes(bufferSize));
    }

    public SSLSocket getSocket() {
        return socket;
    }

    public void stopConnection() throws IOException {
        in.close();
        out.close();
        socket.close();
    }

    public void greet() throws IOException {
        //construct clientHello message to greet server
        Fusion.ClientHello clientHello = Fusion.ClientHello.newBuilder()
                .setVersion(ByteString.copyFrom("alpha13".getBytes()))
                .setGenesisHash(ByteString.copyFrom(Hex.decode("6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000")))
                .build();
        Fusion.ClientMessage clientMessage = Fusion.ClientMessage.newBuilder()
                .setClienthello(clientHello)
                .build();
        //send message to server
        this.sendMessage(clientMessage);
        Fusion.ServerMessage serverMessage = this.receiveMessage(5000);

        //check if message received is serverhello type
        if(serverMessage.hasServerhello()) {
            Fusion.ServerHello serverHello = serverMessage.getServerhello();
            System.out.println(serverHello);
            this.numComponents = serverHello.getNumComponents();
            this.componentFeeRate = serverHello.getComponentFeerate();
            this.minExcessFee = serverHello.getMinExcessFee();
            this.maxExcessFee = serverHello.getMaxExcessFee();
            for(long tier : serverHello.getTiersList()) {
                //construct tiers list
                availableTiers.add(new Tier(tier));
            }

            if(this.coins.isEmpty()) {
                System.out.println("Started with no coins");
                return;
            }

            this.allocateOutputs();
        }
    }

    public void allocateOutputs() {
        this.inputs = this.coins;
        long numInputs = this.inputs.size();

        long maxComponents = Math.min(numComponents, MAX_COMPONENTS);
        long maxOutputs = maxComponents - numInputs;
        if(maxOutputs < 1) {
            System.out.println("Too many inputs (" + numInputs + " >= " + maxComponents);
            return;
        }

        HashMap<String, ECKey> uniqueKeys = new HashMap<>();
        for(Pair<TransactionOutput, ECKey> pair : this.inputs) {
            String key = pair.getRight().getPublicKeyAsHex();
            if(!uniqueKeys.containsKey(key)) {
                uniqueKeys.put(key, pair.getRight());
            }
        }
        long numDistinct = uniqueKeys.size();
        long minOutputs = Math.max(MIN_TX_COMPONENTS - numDistinct, 1);

        if(maxOutputs < minOutputs) {
            System.out.println("Too few distinct inputs selected (" + numDistinct + "); cannot satisfy output count constraint (>=" + minOutputs + ", <=" + maxOutputs + ")");
            return;
        }

        long sumInputsValue = 0;
        long inputFees = 0;
        for(Pair<TransactionOutput, ECKey> pair : this.inputs) {
            sumInputsValue += pair.getLeft().getValue().value;
            long sizeOfInput = sizeOfInput(pair.getRight().getPubKey());
            long componentFee = componentFee(sizeOfInput, this.componentFeeRate);
            inputFees += componentFee;
        }
        long availableForOutputs = (sumInputsValue - inputFees - this.minExcessFee);
        long feePerOutput = componentFee(34, this.componentFeeRate);
        long offsetPerOutput = MIN_OUTPUT + feePerOutput;

        if(availableForOutputs < offsetPerOutput) {
            System.out.println("Selected inputs had too little value");
            return;
        }

        Random rng = new Random();
        HashMap<Long, ArrayList<Long>> tierOutputs = new HashMap<>();
        HashMap<Long, Long> excessFees = new HashMap<>();
        for(Tier tier : this.availableTiers) {
            long fuzzFeeMax = tier.getTierSize() / 1000000;
            long fuzzFeeMaxReduced = Math.min(Math.min(fuzzFeeMax, MAX_EXCESS_FEE - this.minExcessFee), this.maxExcessFee - this.minExcessFee);
            if(fuzzFeeMaxReduced < 0)
                continue;

            long fuzzFee = rng.nextInt((int) (fuzzFeeMaxReduced + 1));
            long reducedAvailableForOutputs = availableForOutputs - fuzzFee;

            if(fuzzFee > fuzzFeeMaxReduced && fuzzFeeMaxReduced > fuzzFeeMax)
                continue;

            if(reducedAvailableForOutputs < offsetPerOutput)
                continue;

            ArrayList<Long> outputs = randomOutputsForTier(rng, reducedAvailableForOutputs, tier, offsetPerOutput, maxOutputs);
            if(outputs.isEmpty() || outputs.size() < minOutputs)
                continue;

            ArrayList<Long> adjustedOutputs = new ArrayList<>();
            for(long output : outputs) {
                adjustedOutputs.add(output - feePerOutput);
            }

            if((this.inputs.size() + adjustedOutputs.size()) > MAX_COMPONENTS)
                continue;

            excessFees.put(tier.getTierSize(), (sumInputsValue - inputFees - reducedAvailableForOutputs));
            tierOutputs.put(tier.getTierSize(), outputs);
        }

        this.tierOutputs = tierOutputs;
        System.out.println("Possible tiers: " + tierOutputs);
        this.registerAndWait();
    }

    public ArrayList<Long> randomOutputsForTier(Random rng, long inputAmount, Tier tier, long offset, long maxCount) {
        if(inputAmount < offset)
            return new ArrayList<>();

        double lambd = 1./tier.getTierSize();
        long remaining = inputAmount;
        ArrayList<Double> values = new ArrayList<>();
        for(int x = 0; x < maxCount+1; x++) {
            double val = expovariate(rng, lambd);
            remaining -= Math.ceil(val) + offset;
            if(remaining < 0)
                break;
            values.add(val);
        }

        if(values.size() > maxCount) return new ArrayList<>();
        if(values.isEmpty()) return new ArrayList<>();

        long desiredRandomSum = inputAmount - values.size() * offset;
        if(desiredRandomSum < 0) {
            return new ArrayList<>();
        }

        ArrayList<Double> cumSum = runningSum(values);
        double sum = 0;
        for(double val : values) {
            sum += val;
        }

        double rescale = desiredRandomSum / sum;
        ArrayList<Long> normedCumSum = new ArrayList<>();
        for(double val : cumSum) {
            normedCumSum.add(Math.round(rescale * val));
        }
        long normedSum = normedCumSum.get(normedCumSum.size()-1);

        if(normedSum != desiredRandomSum) {
            return new ArrayList<>();
        }

        ArrayList<Long> concat = new ArrayList<>();
        concat.add(0L);
        concat.addAll(normedCumSum);
        List<List<Long>> zipped = zip(normedCumSum, concat);

        ArrayList<Long> differences = new ArrayList<>();
        for(List<Long> pair : zipped) {
            if(pair.size() > 1) {
                long a = pair.get(0);
                long b = pair.get(1);
                differences.add(a - b);
            }
        }
        ArrayList<Long> result = new ArrayList<>();
        for(long difference : differences) {
            result.add(offset + difference);
        }

        long resultSum = 0;
        for(long val : result) {
            resultSum += val;
        }

        if(resultSum == inputAmount) {
            return result;
        } else {
            return new ArrayList<>();
        }
    }

    public void registerAndWait() {
        Fusion.JoinPools joinPools = Fusion.JoinPools.newBuilder()
                .addAllTiers(this.tierOutputs.keySet())
                .build();
        Fusion.ClientMessage clientMessage = Fusion.ClientMessage.newBuilder()
                .setJoinpools(joinPools)
                .build();
        try {
            this.sendMessage(clientMessage);
            System.out.println("Registered for tiers.");

            new Thread() {
                @Override
                public void run() {
                    Fusion.ServerMessage serverMessage;
                    while(true) {
                        System.out.println("waiting...");
                        try {
                            serverMessage = receiveMessage(10000);
                            if(serverMessage != null) {
                                if(serverMessage.hasFusionbegin()) {
                                    System.out.println("STARTING FUSION!");
                                    break;
                                }
                            }
                        } catch (IOException ignored) {
                        }
                    }

                    if(serverMessage.hasFusionbegin()) {
                        startCovert(serverMessage);
                    }
                }
            }.start();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void startCovert(Fusion.ServerMessage serverMessage) {
        Fusion.FusionBegin fusionBegin = serverMessage.getFusionbegin();
        this.tier = fusionBegin.getTier();
        ArrayList<Long> outputs = tierOutputs.get(this.tier);
        for(long output : outputs) {
            Address address = wallet.freshChangeAddress();
            Script script = ScriptBuilder.createOutputScript(address);
            this.outputs.add(Pair.of(script, output));
        }

        System.out.println(fusionBegin);
        System.out.println("covert domain: " + fusionBegin.getCovertDomain().toStringUtf8());

        this.runRound();
    }

    private void runRound() {
        try {
            Fusion.ServerMessage serverMessage = this.receiveMessage((2 * WARMUP_SLOP + STANDARD_TIMEOUT)*1000);
            if(serverMessage.hasStartround()) {
                Fusion.StartRound startRound = serverMessage.getStartround();
                long roundTime = startRound.getServerTime();
                long ourTime = System.currentTimeMillis() / 1000;
                System.out.println("roundtime: " + roundTime);
                System.out.println("ourtime: " + ourTime);

                long clockMismatch = roundTime - ourTime;
                if (Math.abs(clockMismatch) > clockMismatch) {
                    return;
                }

                long inputFees = 0;
                for(Pair<TransactionOutput, ECKey> pair : this.inputs) {
                    inputFees += componentFee(sizeOfInput(pair.getRight().getPubKey()), this.componentFeeRate);
                }

                long outputFees = this.tierOutputs.get(tier).size() * componentFee(34, this.componentFeeRate);

                long sumIn = 0;
                for(Pair<TransactionOutput, ECKey> pair : this.inputs) {
                    sumIn += pair.getLeft().getValue().value;
                }

                long sumOut = 0;
                for(long output : this.tierOutputs.get(this.tier)) {
                    sumOut += output;
                }

                long totalFee = sumIn - sumOut;
                long excessFee = totalFee - inputFees - outputFees;

                byte[] roundPubKey = startRound.getRoundPubkey().toByteArray();
                List<ByteString> blindNoncePoints = startRound.getBlindNoncePointsList();

                if(blindNoncePoints.size() != this.numComponents) {
                    System.out.println("blind nonce miscount");
                    return;
                }

                long numBlanks = this.numComponents - this.inputs.size() - this.tierOutputs.get(this.tier).size();

                GeneratedComponents generatedComponents = genComponents(numBlanks, this.inputs, this.outputs, componentFeeRate);
                if(!BigInteger.valueOf(excessFee).equals(generatedComponents.getSumAmounts())) {
                    System.out.println("excess fee does not equal pedersen amount");
                    return;
                }
                if(blindNoncePoints.size() != generatedComponents.getComponents().size()) {
                    System.out.println("Error! Mismatched size! " + blindNoncePoints.size() + " vs. " + generatedComponents.getComponents().size());
                    return;
                }

                ArrayList<ByteString> blindSignatureRequestsByteString = new ArrayList<>();
                ArrayList<SchnorrBlindSignatureRequest> blindSignatureRequests = new ArrayList<>();
                for(int x = 0; x < blindNoncePoints.size(); x++) {
                    byte[] R = blindNoncePoints.get(x).toByteArray();
                    byte[] compSer = generatedComponents.getComponents().get(x).getCompSer();
                    SchnorrBlindSignatureRequest schnorrBlindSignatureRequest = new SchnorrBlindSignatureRequest(roundPubKey, R, Sha256Hash.hash(compSer));
                    blindSignatureRequestsByteString.add(ByteString.copyFrom(schnorrBlindSignatureRequest.getRequest()));
                    blindSignatureRequests.add(schnorrBlindSignatureRequest);
                }

                ArrayList<ByteString> myCommitments = new ArrayList<>();
                for(Component component : generatedComponents.getComponents()) {
                    ByteString byteString = ByteString.copyFrom(component.getCommitSer());
                    myCommitments.add(byteString);
                }

                ArrayList<ByteString> myComponents = new ArrayList<>();
                for(Component component : generatedComponents.getComponents()) {
                    ByteString byteString = ByteString.copyFrom(component.getCompSer());
                    myComponents.add(byteString);
                }

                byte[] randomNumber = new SecureRandom().generateSeed(32);

                Fusion.PlayerCommit playerCommit = Fusion.PlayerCommit.newBuilder()
                        .setRandomNumberCommitment(ByteString.copyFrom(Sha256Hash.hash(randomNumber)))
                        .setPedersenTotalNonce(ByteString.copyFrom(generatedComponents.getPedersenTotalNonce()))
                        .setExcessFee(excessFee)
                        .addAllInitialCommitments(myCommitments)
                        .addAllBlindSigRequests(blindSignatureRequestsByteString)
                        .build();
                Fusion.ClientMessage clientMessage = Fusion.ClientMessage.newBuilder()
                        .setPlayercommit(playerCommit)
                        .build();
                this.sendMessage(clientMessage);

                Fusion.ServerMessage blindSigServerMessage = this.receiveMessage(5000);

                if(blindSigServerMessage.hasBlindsigresponses()) {
                    Fusion.BlindSigResponses blindSigResponses = blindSigServerMessage.getBlindsigresponses();
                    ArrayList<byte[]> scalars = new ArrayList<>();
                    for(ByteString sByteString : blindSigResponses.getScalarsList()) {
                        scalars.add(sByteString.toByteArray());
                    }

                    ArrayList<byte[]> blindSigs = new ArrayList<>();
                    for(int x = 0; x < scalars.size(); x++) {
                        SchnorrBlindSignatureRequest r = blindSignatureRequests.get(x);
                        byte[] sig = r.blindFinalize(scalars.get(x));
                        blindSigs.add(sig);
                    }

                    ArrayList<Fusion.CovertComponent> covertComponents = new ArrayList<>();
                    for(int x = 0; x < blindSigs.size(); x++) {
                        ByteString component = myComponents.get(x);
                        byte[] sig = blindSigs.get(x);
                        Fusion.CovertComponent covertComponent = Fusion.CovertComponent.newBuilder()
                                .setRoundPubkey(ByteString.copyFrom(roundPubKey))
                                .setComponent(component)
                                .setSignature(ByteString.copyFrom(sig))
                                .build();
                        covertComponents.add(covertComponent);
                    }
                    System.out.println("blindsigresponse::");
                    System.out.println(blindSigResponses);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private GeneratedComponents genComponents(long numBlanks, ArrayList<Pair<TransactionOutput, ECKey>> inputs, ArrayList<Pair<Script, Long>> outputs, long componentFeeRate) {
        ArrayList<Pair<Fusion.Component, Long>> components = new ArrayList<>();

        //inputs
        for(Pair<TransactionOutput, ECKey> pair : inputs) {
            long fee = componentFee(sizeOfInput(pair.getRight().getPubKey()), componentFeeRate);
            long value = pair.getLeft().getValue().value;
            Fusion.InputComponent inputComponent = Fusion.InputComponent.newBuilder()
                    .setPrevTxid(ByteString.copyFrom(pair.getLeft().getOutPointFor().getHash().getReversedBytes()))
                    .setPrevIndex((int)pair.getLeft().getOutPointFor().getIndex())
                    .setPubkey(ByteString.copyFrom(pair.getRight().getPubKey()))
                    .setAmount(value)
                    .build();
            Fusion.Component component = Fusion.Component.newBuilder()
                    .setInput(inputComponent)
                    .build();
            components.add(Pair.of(component, +value-fee));
        }

        //outputs
        for(Pair<Script, Long> pair : outputs) {
            long fee = componentFee(sizeOfOutput(pair.getLeft().getProgram()), componentFeeRate);
            long value = pair.getRight();
            Fusion.OutputComponent outputComponent = Fusion.OutputComponent.newBuilder()
                    .setAmount(value)
                    .setScriptpubkey(ByteString.copyFrom(pair.getLeft().getProgram()))
                    .build();
            Fusion.Component component = Fusion.Component.newBuilder()
                    .setOutput(outputComponent)
                    .build();
            components.add(Pair.of(component, +value-fee));
        }

        for(int x = 0; x < numBlanks; x++) {
            Fusion.BlankComponent blankComponent = Fusion.BlankComponent.newBuilder()
                    .build();
            Fusion.Component component = Fusion.Component.newBuilder()
                    .setBlank(blankComponent)
                    .build();
            components.add(Pair.of(component, 0L));
        }

        ArrayList<Component> resultList = new ArrayList<>();
        BigInteger sumNonce = BigInteger.ZERO;
        BigInteger sumAmounts = BigInteger.ZERO;
        //gen commitments
        int cNum = 0;
        for(Pair<Fusion.Component, Long> pair : components) {
            cNum++;
            long commitAmount = pair.getRight();
            byte[] salt = new SecureRandom().generateSeed(32);
            Fusion.Component modifiedComponent = pair.getLeft().toBuilder().setSaltCommitment(ByteString.copyFrom(Sha256Hash.hash(salt))).build();
            byte[] compSer = modifiedComponent.toByteArray();

            try {
                Pedersen.Commitment commitment = pedersen.commit(commitAmount);
                sumNonce = sumNonce.add(commitment.getNonce());
                sumAmounts = sumAmounts.add(BigInteger.valueOf(commitAmount));

                ECKey ecKey = new ECKey();
                Fusion.InitialCommitment initialCommitment = Fusion.InitialCommitment.newBuilder()
                        .setSaltedComponentHash(ByteString.copyFrom(Sha256Hash.hash(ArrayUtils.addAll(salt, compSer))))
                        .setAmountCommitment(ByteString.copyFrom(commitment.getpUncompressed()))
                        .setCommunicationKey(ByteString.copyFrom(ecKey.getPubKey()))
                        .build();

                byte[] commitSer = initialCommitment.toByteArray();
                Fusion.Proof proof = Fusion.Proof.newBuilder()
                        .setSalt(ByteString.copyFrom(salt))
                        .setPedersenNonce(ByteString.copyFrom(commitment.getNonce().toByteArray()))
                        .build();

                resultList.add(new Component(commitSer, cNum, compSer, proof, ecKey));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        Collections.sort(resultList);

        sumNonce = sumNonce.mod(pedersen.getOrder());
        byte[] pedersenTotalNonce = sumNonce.toByteArray();

        return new GeneratedComponents(resultList, sumAmounts, pedersenTotalNonce);
    }

    private long componentFee(long size, long feeRate) {
        return (size * feeRate + 999) / 1000;
    }

    private long sizeOfInput(byte[] pubKey) {
        return 108 + pubKey.length;
    }

    private long sizeOfOutput(byte[] scriptPubKey) {
        return 9 + scriptPubKey.length;
    }

    public double expovariate(Random rng, double lambda) {
        return -Math.log(1.0-rng.nextDouble())/lambda;
    }

    public ArrayList<Double> runningSum(ArrayList<Double> nums) {
        ArrayList<Double> out = new ArrayList<>(nums);
        for (int iElement = 1; iElement < nums.size(); iElement++) {
            out.set(iElement, out.get(iElement - 1) + nums.get(iElement));
        }
        return out;
    }

    public <T> List<List<T>> zip(List<T>... lists) {
        List<List<T>> zipped = new ArrayList<List<T>>();
        for (List<T> list : lists) {
            for (int i = 0, listSize = list.size(); i < listSize; i++) {
                List<T> list2;
                if (i >= zipped.size())
                    zipped.add(list2 = new ArrayList<T>());
                else
                    list2 = zipped.get(i);
                list2.add(list.get(i));
            }
        }
        return zipped;
    }
}
