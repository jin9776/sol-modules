package sol.link.module.snmp;//package sol.link.module.snmp;
//
//import org.snmp4j.CommandResponder;
//import org.snmp4j.CommandResponderEvent;
//import org.snmp4j.smi.Address;
//
//public class TrapReceiver implements CommandResponder {
//
//    @Override
//    public <A extends Address> void processPdu(CommandResponderEvent<A> event) {
//        /*
//        if (start < 0) {
//			start = System.currentTimeMillis() - 1;
//		}
//		n++;
//		if ((n % 100 == 1)) {
//			System.out.println("Processed "
//					+ (n / (double) (System.currentTimeMillis() - start))
//					* 1000 + "/s, total=" + n);
//		}
//
//		StringBuffer msg = new StringBuffer();
//		msg.append(event.toString());
//		Vector<? extends VariableBinding> varBinds = event.getPDU()
//				.getVariableBindings();
//		if (varBinds != null && !varBinds.isEmpty()) {
//			Iterator<? extends VariableBinding> varIter = varBinds.iterator();
//			while (varIter.hasNext()) {
//				VariableBinding var = varIter.next();
//				msg.append(var.toString()).append(";");
//			}
//		}
//		System.out.println("Message Received: " + msg.toString());
//         */
//    }
//}
