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
// List function names and entry point addresses to a file
//@category AWH

import ghidra.app.plugin.core.script.Ingredient;
import ghidra.app.plugin.core.script.IngredientDescription;
import ghidra.app.script.GatherParamPanel;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.io.*;

public class ExportFunctionInfoScriptMine extends GhidraScript {

	@Override
	public void run() throws Exception {
		File outputFile     = new File( getProgramFile().getParentFile(), "AWH_Functions.txt");
		PrintWriter pWriter = new PrintWriter(new FileOutputStream(outputFile));
		SymbolTable symbolTable = currentProgram.getSymbolTable();
		SymbolIterator allSymbols = symbolTable.getAllSymbols(true);
		while( allSymbols.hasNext() && !monitor.isCancelled() ){
			Symbol symbol = allSymbols.next();
			String name  = symbol.getName(true);
			Address addr = symbol.getAddress();
			pWriter.println("/* Symbol_ADDR_"    + addr.toString("0x") + "      Symbol_NAME_ " + name + " */");
		}

		Listing listing = currentProgram.getListing();
		FunctionIterator iter = listing.getFunctions(true);
		while (iter.hasNext() && !monitor.isCancelled()) {
			Function f = iter.next();
			String fName = f.getName();
			Address entry = f.getEntryPoint();
			if (entry == null) {
				pWriter.println("/* FUNCTION_ADDR_NO_ENTRY_POINT FUNCTION_NAME_ " + fName + " */");
				println("WARNING: no entry point for " + fName);
			}
			else {
				pWriter.println("/* FUNCTION_ADDR_" + entry.toString("0x") + "    FUNCTION_NAME_ " + fName + " */");
			}
		}
		pWriter.close();
	}

}
