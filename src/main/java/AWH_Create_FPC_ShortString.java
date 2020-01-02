/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// Labels a VMT table based on its string name
//@category AWH
//@menupath AWH.Short_String
//@toolbar str.png

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Symbol;

public class AWH_Create_FPC_ShortString extends GhidraScript {

	/**
	 * The run method is where the script specific code is placed.
	 *
	 * @throws Exception if any exception occurs.
	 */
	@Override
	protected void run() throws Exception {
		Address offsetAddr  = currentAddress.add(0x00);
		Address offsetAddr1 = currentAddress.add(0x01);
		clearListing( offsetAddr );
		clearListing( offsetAddr1 );
		Data dLen = createByte( offsetAddr );
		int len = (int)((Scalar) dLen.getValue()).getValue();
		Data nameData = createAsciiString( currentAddress.add(0x01), len );
		String value = (String) nameData.getValue();
		Symbol strSymbol = createLabel(currentAddress, value, true);
	}
}
