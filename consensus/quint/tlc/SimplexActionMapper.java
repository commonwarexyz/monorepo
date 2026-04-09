package tlc2.controlled.protocol;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import tlc2.tool.Action;
import tlc2.value.impl.Enumerable;
import tlc2.value.impl.IntValue;
import tlc2.value.impl.StringValue;
import tlc2.value.impl.Value;
import tlc2.value.impl.ValueEnumeration;

/**
 * Maps JSON action descriptions to TLC Actions for the simplex consensus
 * specification compiled from quint -> TLA+.
 *
 * The compiled spec exposes the following top level actions in `main_replica_step`:
 *
 *   main_replica_propose                 (id, new_payload, parent_view)
 *   main_replica_on_notarize             (id, vote = {proposal, sig})
 *   main_replica_on_finalize             (id, vote = {proposal, sig})
 *   main_replica_on_nullify              (id, vote = {view, sig})
 *   main_replica_on_notarization_cert    (id, cert_view, cert_parent, cert_payload, cert_sender)
 *   main_replica_on_finalization_cert    (id, cert_view, cert_parent, cert_payload, cert_sender)
 *   main_replica_on_nullification_cert   (id, cert_view, cert_sender)
 *   main_replica_on_timeout              (id, expired)
 *   main_replica_send_notarize_vote      (vote = {proposal, sig})
 *   main_replica_send_finalize_vote      (vote = {proposal, sig})
 *   main_replica_send_nullify_vote       (vote = {view, sig})
 *   main_replica_send_notarization_cert  (cert_view, cert_parent, cert_payload, ghost_sender, signers)
 *   main_replica_send_finalization_cert  (cert_view, cert_parent, cert_payload, ghost_sender, signers)
 *   main_replica_send_nullification_cert (cert_view, ghost_sender, signers)
 *
 * Because each disjunct in `main_replica_step` is `\E ... : main_replica_X(...)`, TLC
 * binds the outer existential variables (`main_replica_id`, `main_replica_vote_view`, ...)
 * in the Action's Context. Quint may add a `_NNNN` disambiguation suffix when
 * the same name is reused across helper actions, so we look up params by
 * prefix (see {@link #findValueByPrefix}).
 *
 * The accepted JSON action shapes are:
 *
 *   {"name": "propose",        "params": {"id": "n0", "payload": "val_b0", "parent": 0}}
 *   {"name": "on_notarize",    "params": {"id": "n1", "view": 1, "payload": "val_b0", "parent": 0, "sig": "n0"}}
 *   {"name": "on_finalize",    "params": {"id": "n0", "view": 1, "payload": "val_b0", "parent": 0, "sig": "n0"}}
 *   {"name": "on_nullify",     "params": {"id": "n0", "view": 1, "sig": "n0"}}
 *   {"name": "on_timeout",     "params": {"id": "n0", "kind": "leader" | "certification"}}
 *   {"name": "send_notarize_vote", "params": {"view": 1, "payload": "val_b0", "parent": 0, "sig": "n0"}}
 *   {"name": "send_finalize_vote", "params": {"view": 1, "payload": "val_b0", "parent": 0, "sig": "n0"}}
 *   {"name": "send_nullify_vote",  "params": {"view": 1, "sig": "n0"}}
 *   {"name": "send_certificate", "params": {
 *       "type": "notarization" | "nullification" | "finalization",
 *       "proposal": {"view": 1, "parent": 0, "payload": "val_b0"},  // omit for nullification
 *       "view": 1,                                                    // nullification only
 *       "ghost_sender": "n0",
 *       "signatures": ["n0", "n1", "n2"]
 *   }}
 *   {"name": "on_certificate", "params": {
 *       "id": "n0",
 *       "type": "notarization" | "nullification" | "finalization",
 *       "proposal": {"view": 1, "parent": 0, "payload": "val_b0"},  // omit for nullification
 *       "view": 1,                                                    // nullification only
 *       "signatures": ["n0", "n1", "n2"],                             // informational, ignored
 *       "ghost_sender": "n0"
 *   }}
 *
 * The `signatures` field is informational only; the spec looks up the
 * matching cert in `sent_certificates` at runtime by (kind, proposal,
 * ghost_sender), which is unique. The mapper picks the parse-time
 * `main_replica_on_*_cert` action whose outer parameters match the JSON.
 */
public class SimplexActionMapper extends BaseActionMapper {

    private static final String OP_PROPOSE                 = "main_replica_propose";
    private static final String OP_ON_NOTARIZE             = "main_replica_on_notarize";
    private static final String OP_ON_FINALIZE             = "main_replica_on_finalize";
    private static final String OP_ON_NULLIFY              = "main_replica_on_nullify";
    private static final String OP_ON_NOTARIZATION_CERT    = "main_replica_on_notarization_cert";
    private static final String OP_ON_FINALIZATION_CERT    = "main_replica_on_finalization_cert";
    private static final String OP_ON_NULLIFICATION_CERT   = "main_replica_on_nullification_cert";
    private static final String OP_ON_TIMEOUT              = "main_replica_on_timeout";
    private static final String OP_SEND_NOTARIZE_VOTE      = "main_replica_send_notarize_vote";
    private static final String OP_SEND_FINALIZE_VOTE      = "main_replica_send_finalize_vote";
    private static final String OP_SEND_NULLIFY_VOTE       = "main_replica_send_nullify_vote";
    private static final String OP_SEND_NOTARIZATION_CERT  = "main_replica_send_notarization_cert";
    private static final String OP_SEND_FINALIZATION_CERT  = "main_replica_send_finalization_cert";
    private static final String OP_SEND_NULLIFICATION_CERT = "main_replica_send_nullification_cert";

    private static final String VAR_ID           = "main_replica_id";
    private static final String VAR_NEW_PAYLOAD  = "main_replica_new_payload";
    private static final String VAR_PARENT_VIEW  = "main_replica_parent_view";
    private static final String VAR_VOTE_VIEW    = "main_replica_vote_view";
    private static final String VAR_VOTE_PARENT  = "main_replica_vote_parent";
    private static final String VAR_VOTE_PAYLOAD = "main_replica_vote_payload";
    private static final String VAR_VOTE_SIG     = "main_replica_vote_sig";
    private static final String VAR_EXPIRED      = "main_replica_expired";
    private static final String VAR_CERT_VIEW    = "main_replica_cert_view";
    private static final String VAR_CERT_PARENT  = "main_replica_cert_parent";
    private static final String VAR_CERT_PAYLOAD = "main_replica_cert_payload";
    private static final String VAR_CERT_SENDER  = "main_replica_cert_sender";
    private static final String VAR_GHOST_SENDER = "main_replica_ghost_sender";
    private static final String VAR_SIGNERS      = "main_replica_signers";

    private static final String LEADER_TIMEOUT_KIND        = "LEADER_TIMEOUT_KIND";
    private static final String CERTIFICATION_TIMEOUT_KIND = "CERTIFICATION_TIMEOUT_KIND";

    public SimplexActionMapper(List<Action> enabledActions) {
        super(enabledActions);
    }

    @Override
    protected Action mapAction(AbstractAction abstractAction) {
        Action result;
        try {
            switch (abstractAction.name) {
                case "propose":
                    result = mapPropose(abstractAction);
                    break;
                case "on_notarize":
                    result = mapOnVote(OP_ON_NOTARIZE, abstractAction);
                    break;
                case "on_finalize":
                    result = mapOnVote(OP_ON_FINALIZE, abstractAction);
                    break;
                case "on_nullify":
                    result = mapOnNullify(abstractAction);
                    break;
                case "on_certificate":
                    result = mapOnCertificate(abstractAction);
                    break;
                case "on_timeout":
                    result = mapOnTimeout(abstractAction);
                    break;
                case "send_notarize_vote":
                    result = mapSendVoteWithProposal(OP_SEND_NOTARIZE_VOTE, abstractAction);
                    break;
                case "send_finalize_vote":
                    result = mapSendVoteWithProposal(OP_SEND_FINALIZE_VOTE, abstractAction);
                    break;
                case "send_nullify_vote":
                    result = mapSendNullifyVote(abstractAction);
                    break;
                case "send_certificate":
                    result = mapSendCertificate(abstractAction);
                    break;
                default:
                    result = null;
                    break;
            }
        } catch (Exception e) {
            System.out.println("[SimplexActionMapper] mapAction error for "
                    + abstractAction.name + ": " + e.getMessage());
            result = null;
        }
        return result;
    }

    private Action mapPropose(AbstractAction a) {
        String id = readString(a, "id");
        String payload = readString(a, "payload");
        Integer parent = readInt(a, "parent");
        if (id == null || payload == null || parent == null) {
            return null;
        }
        List<Action> candidates = enabledActionMap.get(OP_PROPOSE);
        if (candidates == null) {
            return null;
        }
        for (Action action : candidates) {
            Map<String, Value> params = action.getParams();
            if (!stringEquals(params.get(VAR_ID), id)) continue;
            if (!stringEquals(params.get(VAR_NEW_PAYLOAD), payload)) continue;
            if (!intEquals(params.get(VAR_PARENT_VIEW), parent)) continue;
            return action;
        }
        return null;
    }

    private Action mapOnVote(String operatorName, AbstractAction a) {
        String id = readString(a, "id");
        Integer view = readInt(a, "view");
        Integer parent = readInt(a, "parent");
        String payload = readString(a, "payload");
        String sig = readString(a, "sig");
        if (id == null || view == null || parent == null || payload == null || sig == null) {
            return null;
        }
        List<Action> candidates = enabledActionMap.get(operatorName);
        if (candidates == null) {
            return null;
        }
        for (Action action : candidates) {
            Map<String, Value> params = action.getParams();
            if (!stringEquals(params.get(VAR_ID), id)) continue;
            if (!intEquals(params.get(VAR_VOTE_VIEW), view)) continue;
            if (!intEquals(params.get(VAR_VOTE_PARENT), parent)) continue;
            if (!stringEquals(params.get(VAR_VOTE_PAYLOAD), payload)) continue;
            if (!stringEquals(params.get(VAR_VOTE_SIG), sig)) continue;
            return action;
        }
        return null;
    }

    private Action mapOnNullify(AbstractAction a) {
        String id = readString(a, "id");
        Integer view = readInt(a, "view");
        String sig = readString(a, "sig");
        if (id == null || view == null || sig == null) {
            return null;
        }
        List<Action> candidates = enabledActionMap.get(OP_ON_NULLIFY);
        if (candidates == null) {
            return null;
        }
        for (Action action : candidates) {
            Map<String, Value> params = action.getParams();
            if (!stringEquals(params.get(VAR_ID), id)) continue;
            if (!intEquals(params.get(VAR_VOTE_VIEW), view)) continue;
            if (!stringEquals(params.get(VAR_VOTE_SIG), sig)) continue;
            return action;
        }
        return null;
    }

    /**
     * Dispatches `on_certificate` to the right `main_replica_on_*_cert`
     * action based on the JSON `type` field. The mapper picks the action
     * whose parse-time outer parameters match the JSON `id`, proposal
     * subject, and `ghost_sender`. The cert's signatures are looked up at
     * runtime in `sent_certificates`; the JSON `signatures` field is
     * informational only.
     */
    private Action mapOnCertificate(AbstractAction a) {
        String id = readString(a, "id");
        String kind = readString(a, "type");
        String sender = readString(a, "ghost_sender");
        if (id == null || kind == null || sender == null) {
            return null;
        }
        if (kind.equalsIgnoreCase("notarization")) {
            return mapNotarizationOrFinalizationCert(OP_ON_NOTARIZATION_CERT, a, id, sender);
        } else if (kind.equalsIgnoreCase("finalization")) {
            return mapNotarizationOrFinalizationCert(OP_ON_FINALIZATION_CERT, a, id, sender);
        } else if (kind.equalsIgnoreCase("nullification")) {
            return mapNullificationCert(a, id, sender);
        }
        return null;
    }

    private Action mapNotarizationOrFinalizationCert(
            String operatorName, AbstractAction a, String id, String sender) {
        Map<String, Object> proposal = readMap(a, "proposal");
        if (proposal == null) {
            return null;
        }
        Integer view = readIntFrom(proposal, "view");
        Integer parent = readIntFrom(proposal, "parent");
        String payload = readStringFrom(proposal, "payload");
        if (view == null || parent == null || payload == null) {
            return null;
        }
        List<Action> candidates = enabledActionMap.get(operatorName);
        if (candidates == null) {
            return null;
        }
        for (Action action : candidates) {
            Map<String, Value> params = action.getParams();
            if (!stringEquals(findValueByPrefix(params, VAR_ID), id)) continue;
            if (!intEquals(findValueByPrefix(params, VAR_CERT_VIEW), view)) continue;
            if (!intEquals(findValueByPrefix(params, VAR_CERT_PARENT), parent)) continue;
            if (!stringEquals(findValueByPrefix(params, VAR_CERT_PAYLOAD), payload)) continue;
            if (!stringEquals(findValueByPrefix(params, VAR_CERT_SENDER), sender)) continue;
            return action;
        }
        return null;
    }

    private Action mapNullificationCert(AbstractAction a, String id, String sender) {
        Integer view = readInt(a, "view");
        if (view == null) {
            return null;
        }
        List<Action> candidates = enabledActionMap.get(OP_ON_NULLIFICATION_CERT);
        if (candidates == null) {
            return null;
        }
        for (Action action : candidates) {
            Map<String, Value> params = action.getParams();
            if (!stringEquals(findValueByPrefix(params, VAR_ID), id)) continue;
            if (!intEquals(findValueByPrefix(params, VAR_CERT_VIEW), view)) continue;
            if (!stringEquals(findValueByPrefix(params, VAR_CERT_SENDER), sender)) continue;
            return action;
        }
        return null;
    }

    /**
     * Dispatches `send_notarize_vote` / `send_finalize_vote` to the
     * matching parse-time action. These actions inject a vote directly
     * into `sent_*_votes` without running the protocol; they take a
     * single vote record (no replica id), so we only match by view,
     * parent, payload, and sig.
     */
    private Action mapSendVoteWithProposal(String operatorName, AbstractAction a) {
        Integer view = readInt(a, "view");
        Integer parent = readInt(a, "parent");
        String payload = readString(a, "payload");
        String sig = readString(a, "sig");
        if (view == null || parent == null || payload == null || sig == null) {
            return null;
        }
        List<Action> candidates = enabledActionMap.get(operatorName);
        if (candidates == null) {
            return null;
        }
        for (Action action : candidates) {
            Map<String, Value> params = action.getParams();
            if (!intEquals(findValueByPrefix(params, VAR_VOTE_VIEW), view)) continue;
            if (!intEquals(findValueByPrefix(params, VAR_VOTE_PARENT), parent)) continue;
            if (!stringEquals(findValueByPrefix(params, VAR_VOTE_PAYLOAD), payload)) continue;
            if (!stringEquals(findValueByPrefix(params, VAR_VOTE_SIG), sig)) continue;
            return action;
        }
        return null;
    }

    /**
     * Dispatches `send_nullify_vote` to the matching parse-time action.
     * Nullify votes carry only a view and a sig.
     */
    private Action mapSendNullifyVote(AbstractAction a) {
        Integer view = readInt(a, "view");
        String sig = readString(a, "sig");
        if (view == null || sig == null) {
            return null;
        }
        List<Action> candidates = enabledActionMap.get(OP_SEND_NULLIFY_VOTE);
        if (candidates == null) {
            return null;
        }
        for (Action action : candidates) {
            Map<String, Value> params = action.getParams();
            if (!intEquals(findValueByPrefix(params, VAR_VOTE_VIEW), view)) continue;
            if (!stringEquals(findValueByPrefix(params, VAR_VOTE_SIG), sig)) continue;
            return action;
        }
        return null;
    }

    /**
     * Dispatches `send_certificate` to the right
     * `main_replica_send_*_cert` action based on the JSON `type` field.
     * The signer set is taken from the JSON `signatures` field; the spec
     * verifies each signer has a corresponding vote in `sent_*_votes`.
     * Required JSON params:
     *   {"type": "notarization" | "finalization" | "nullification",
     *    "proposal": {"view", "parent", "payload"},  // omit for nullification
     *    "view": int,                                // nullification only
     *    "ghost_sender": "n0",
     *    "signatures": ["n0", "n1", "n2"]}
     */
    private Action mapSendCertificate(AbstractAction a) {
        String kind = readString(a, "type");
        String sender = readString(a, "ghost_sender");
        Set<String> signers = readStringList(a, "signatures");
        if (kind == null || sender == null || signers == null) {
            return null;
        }
        if (kind.equalsIgnoreCase("notarization")) {
            return mapSendNotarizationOrFinalizationCert(OP_SEND_NOTARIZATION_CERT, a, sender, signers);
        } else if (kind.equalsIgnoreCase("finalization")) {
            return mapSendNotarizationOrFinalizationCert(OP_SEND_FINALIZATION_CERT, a, sender, signers);
        } else if (kind.equalsIgnoreCase("nullification")) {
            return mapSendNullificationCert(a, sender, signers);
        }
        return null;
    }

    private Action mapSendNotarizationOrFinalizationCert(
            String operatorName, AbstractAction a, String sender, Set<String> signers) {
        Map<String, Object> proposal = readMap(a, "proposal");
        if (proposal == null) {
            return null;
        }
        Integer view = readIntFrom(proposal, "view");
        Integer parent = readIntFrom(proposal, "parent");
        String payload = readStringFrom(proposal, "payload");
        if (view == null || parent == null || payload == null) {
            return null;
        }
        List<Action> candidates = enabledActionMap.get(operatorName);
        if (candidates == null) {
            return null;
        }
        for (Action action : candidates) {
            Map<String, Value> params = action.getParams();
            if (!intEquals(findValueByPrefix(params, VAR_CERT_VIEW), view)) continue;
            if (!intEquals(findValueByPrefix(params, VAR_CERT_PARENT), parent)) continue;
            if (!stringEquals(findValueByPrefix(params, VAR_CERT_PAYLOAD), payload)) continue;
            if (!stringEquals(findValueByPrefix(params, VAR_GHOST_SENDER), sender)) continue;
            if (!stringSetEquals(findValueByPrefix(params, VAR_SIGNERS), signers)) continue;
            return action;
        }
        return null;
    }

    private Action mapSendNullificationCert(AbstractAction a, String sender, Set<String> signers) {
        Integer view = readInt(a, "view");
        if (view == null) {
            return null;
        }
        List<Action> candidates = enabledActionMap.get(OP_SEND_NULLIFICATION_CERT);
        if (candidates == null) {
            return null;
        }
        for (Action action : candidates) {
            Map<String, Value> params = action.getParams();
            if (!intEquals(findValueByPrefix(params, VAR_CERT_VIEW), view)) continue;
            if (!stringEquals(findValueByPrefix(params, VAR_GHOST_SENDER), sender)) continue;
            if (!stringSetEquals(findValueByPrefix(params, VAR_SIGNERS), signers)) continue;
            return action;
        }
        return null;
    }

    private Action mapOnTimeout(AbstractAction a) {
        String id = readString(a, "id");
        String kind = readString(a, "kind");
        if (id == null || kind == null) {
            return null;
        }
        String expected;
        if (kind.equalsIgnoreCase("leader")) {
            expected = LEADER_TIMEOUT_KIND;
        } else if (kind.equalsIgnoreCase("certification")) {
            expected = CERTIFICATION_TIMEOUT_KIND;
        } else {
            return null;
        }
        List<Action> candidates = enabledActionMap.get(OP_ON_TIMEOUT);
        if (candidates == null) {
            return null;
        }
        for (Action action : candidates) {
            Map<String, Value> params = action.getParams();
            if (!stringEquals(params.get(VAR_ID), id)) continue;
            if (!stringEquals(params.get(VAR_EXPIRED), expected)) continue;
            return action;
        }
        return null;
    }

    private static String readString(AbstractAction a, String key) {
        return readStringFrom(a.params, key);
    }

    private static Integer readInt(AbstractAction a, String key) {
        return readIntFrom(a.params, key);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> readMap(AbstractAction a, String key) {
        Object v = a.params == null ? null : a.params.get(key);
        if (v instanceof Map) {
            return (Map<String, Object>) v;
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private static Set<String> readStringList(AbstractAction a, String key) {
        Object v = a.params == null ? null : a.params.get(key);
        if (!(v instanceof List)) {
            return null;
        }
        Set<String> result = new HashSet<>();
        for (Object item : (List<Object>) v) {
            if (!(item instanceof String)) {
                return null;
            }
            result.add((String) item);
        }
        return result;
    }

    private static String readStringFrom(Map<String, Object> map, String key) {
        Object v = map == null ? null : map.get(key);
        if (v instanceof String) {
            return (String) v;
        }
        return null;
    }

    private static Integer readIntFrom(Map<String, Object> map, String key) {
        Object v = map == null ? null : map.get(key);
        if (v instanceof Number) {
            return ((Number) v).intValue();
        }
        return null;
    }

    private static boolean stringEquals(Value v, String expected) {
        if (!(v instanceof StringValue)) {
            return false;
        }
        return ((StringValue) v).getVal().toString().equals(expected);
    }

    private static boolean intEquals(Value v, int expected) {
        if (!(v instanceof IntValue)) {
            return false;
        }
        return ((IntValue) v).val == expected;
    }

    private static boolean stringSetEquals(Value v, Set<String> expected) {
        if (!(v instanceof Enumerable)) {
            return false;
        }
        Set<String> actual = new HashSet<>();
        ValueEnumeration it = ((Enumerable) v).elements();
        Value e;
        while ((e = it.nextElement()) != null) {
            if (!(e instanceof StringValue)) {
                return false;
            }
            actual.add(((StringValue) e).getVal().toString());
        }
        return actual.equals(expected);
    }

    /**
     * Looks up an action parameter by base name. Quint may add a `_NNNN`
     * disambiguation suffix when the same name is reused across helper
     * actions, so we accept any param whose key is exactly {@code prefix}
     * or {@code prefix + "_" + digits}.
     */
    private static Value findValueByPrefix(Map<String, Value> params, String prefix) {
        Value exact = params.get(prefix);
        if (exact != null) {
            return exact;
        }
        String dashed = prefix + "_";
        for (Map.Entry<String, Value> e : params.entrySet()) {
            String key = e.getKey();
            if (!key.startsWith(dashed)) continue;
            String tail = key.substring(dashed.length());
            if (tail.isEmpty()) continue;
            boolean allDigits = true;
            for (int i = 0; i < tail.length(); i++) {
                if (!Character.isDigit(tail.charAt(i))) {
                    allDigits = false;
                    break;
                }
            }
            if (allDigits) {
                return e.getValue();
            }
        }
        return null;
    }
}
