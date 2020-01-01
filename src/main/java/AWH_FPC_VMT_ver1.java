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
//@keybinding shift ctrl B

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;

public class AWH_FPC_VMT_ver1 extends GhidraScript {
	private AddressFactory  addressFactory;
	private DataTypeManager dataTypeManager;
	private FunctionManager functionManager;
	private Listing         listing;
	private Memory          memory;
	private SymbolTable     symbolTable;

	private DataType    BYTE;
	private DataType    WORD;
	private DataType    DWORD;
	private DataType    QWORD;
	private DataType    PTR;
	private DataType    CSTRING;
	private Address     dataStart;
	private Address     dataEnd;
	private PrintWriter pWriter;

	class VMTField {
		int offset;
		Address vmtStartAddr;
		Address offsetAddr;
		DataType dataType;
		String comment;
		String ptrPrefixSuffix;
		//
		int         qwordValue;
		Address     ptrAddr;
		VMT         parent;
		ShortString shortStr;

		VMTField( int arg_offset, DataType arg_dataType, String arg_comment, String arg_ptrPrefixSuffix ) {
			this.offset          = arg_offset;
			this.dataType        = arg_dataType;
			this.comment         = arg_comment;
			this.ptrPrefixSuffix = arg_ptrPrefixSuffix;
			//pWriter.printf("VMT Field:      %03d %-20s %-25s %-40s\n", offset, dataType.getPathName(), ptrNamePrefix, comment);
		}

		void initValues(Address startAddr, VMTField classNameField) throws Exception {
			vmtStartAddr = startAddr;
			offsetAddr = vmtStartAddr.add(offset);
			// print out symbols found at this VMT address
			for( Symbol symbol : symbolTable.getSymbols(offsetAddr) ){
				String name = symbol.getName();
				pWriter.println( classNameField.shortStr.value + " Found symbol at " + offsetAddr.toString("0x" ) + ": " + name );
			}
			clearListing( offsetAddr );
			Data data = createData( offsetAddr, dataType );
			listing.getCodeUnitAt(  offsetAddr ).setComment( CodeUnit.EOL_COMMENT, comment );
			//pWriter.printf("VMT Field init: %03d %-20s %-25s %-25s %-40s\n", offset, dataType.getPathName(), ptrNamePrefix, ptrNmaeSuffix, comment);
			if (QWORD.equals(dataType)) {
				qwordValue = (int) ((Scalar) data.getValue()).getValue();
			} else if (PTR.equals(dataType)) {
				ptrAddr = (Address) data.getValue();
				switch( offset ){
					case 0x00: // start of vmt and Instance Size 1
						break;
					case 0x10: // Parent VMT
						if( ptrAddr.getUnsignedOffset() != 0 ) {
							parent = new VMT(ptrAddr);
						} else {
							parent = null;
						}
						break;
					case 0x18: // Classname
						shortStr = new ShortString(ptrAddr);
						// set label for VMT table
						String vmtLabel  = "GL_VMT_" + shortStr.value;
						Symbol vmtSymbol = createLabel(vmtStartAddr, vmtLabel, true);
						int refCount = currentProgram.getReferenceManager().getReferenceCountTo(vmtStartAddr);
						pWriter.printf( "%s VMT name:  %-20s [%03d] 0x%-15s 0x%-15s\n", shortStr.value, vmtSymbol.getName(), refCount, vmtStartAddr, offsetAddr );
						symbolTable.createClass( currentProgram.getGlobalNamespace(), shortStr.value, SourceType.USER_DEFINED);
						break;
					case 0x20: // vmt data Blocks
					case 0x28:
					case 0x30:
					case 0x38:
					case 0x40:
					case 0x48:
					case 0x50:
					case 0x58:
						if( ptrAddr.getUnsignedOffset() != 0 ) {
							String dataFieldLabel = ptrPrefixSuffix + classNameField.shortStr.value;
							Symbol dataFieldSymbol = createLabel(ptrAddr, dataFieldLabel, true);
							pWriter.printf("%s VMT field init: %-20s       0x%-15s\n", classNameField.shortStr.value, dataFieldSymbol.getName(), ptrAddr);
						}
						break;
					default: // class functions
						if( ptrAddr.getUnsignedOffset() != 0 ) {
							vmtStartAddr = startAddr;
							offsetAddr = vmtStartAddr.add(offset);
							pWriter.printf("%s VMT field init:                            0x%-15s\n", classNameField.shortStr.value, ptrAddr);
						}
						break;
				}
			}
		}

		public void createFunc( VMTField vClassName ) throws Exception {
			if( ptrAddr.getUnsignedOffset() != 0 ) {
				String funcName = vClassName.shortStr.value + ptrPrefixSuffix;
				pWriter.println(funcName + " Func start:           " + offsetAddr.toString("0x") + " => " + ptrAddr.toString("0x"));
				Function existingFunc = getFunctionAt(ptrAddr);
				if (existingFunc == null) {
					// function doesn't exist so check if is code
					Instruction existingInstr = getInstructionAt(ptrAddr);
					if (existingInstr == null) {
						// no code at address
						pWriter.println(funcName + " Disassembling at:     " + ptrAddr.toString("0x"));
						clearListing(ptrAddr);
						disassemble(ptrAddr);
						analyzeChanges(currentProgram);
					}
					pWriter.println(funcName + " Creating Func at:     " + ptrAddr.toString("0x"));
					Function newFunc = createFunction(ptrAddr, funcName);
					if (newFunc == null) {
						newFunc = listing.getFunctionAt(ptrAddr);
						if (newFunc == null) {
							pWriter.println(funcName + " Error: null pointer for function at " + ptrAddr.toString("0x"));
							throw new Exception();
						} else {
							pWriter.println(funcName + " Func:                 " + ptrAddr.toString("0x") + " with name: " + newFunc.getName());
						}
					} else {
						pWriter.println(funcName + " Func:                 " + ptrAddr.toString("0x") + " with name: " + newFunc.getName());
					}
					analyzeChanges(currentProgram);
				} else {
					// fuction exist so check name
					String existingName = existingFunc.getName();
					boolean alreadyRenamed = existingName.contains("::");
					if (alreadyRenamed) {
						pWriter.println(funcName + " Func already renamed: " + ptrAddr.toString("0x") + " not done existing name [" + existingName + "] would have done " + existingFunc.getName() + " => " + funcName);
					} else {
						if (!existingFunc.getName().equals(funcName)) {
							pWriter.println(funcName + " Func renaming:        " + ptrAddr.toString("0x") + " with name: " + existingFunc.getName() + " => " + funcName);
							existingFunc.setName(funcName, SourceType.USER_DEFINED);
							analyzeChanges(currentProgram);
						}
					}
				}
				pWriter.println(funcName + " Func end:             " + offsetAddr.toString("0x") + " => " + ptrAddr.toString("0x"));
			}
		}
	}

	class ShortString {
		int    len;
		String value;

		ShortString(Address addr) throws Exception {
			//pWriter.println("-------------------ShortString ["+addr.toString("0x")+"]-------------------");
			Address offsetAddr  = addr.add(0x00);
			Address offsetAddr1 = addr.add(0x01);
			clearListing( offsetAddr );
			clearListing( offsetAddr1 );
			Data dLen = createByte( offsetAddr );
			len = (int)((Scalar) dLen.getValue()).getValue();
			Data nameData = createAsciiString( addr.add(0x01), len );
			value = (String) nameData.getValue();
			Symbol strSymbol = createLabel(addr, value, true);
			//pWriter.println("-------------------ShortString ["+addr.toString("0x")+"] ("+ value +")-------------------");
		}
	}

	class VMT {
	    VMTField vInstanceSize      = new VMTField( 0x00, QWORD, "VMT Instance Size"              , "GL_InstanceSize_"        );
	    VMTField vInstanceSize2     = new VMTField( 0x08, QWORD, "VMT Instance Size 2s Complement", "GL_InstanceSize_2scomp_" );
	    VMTField vParent            = new VMTField( 0x10, PTR  , "VMT Parent"                     , null                      );
	    VMTField vClassName         = new VMTField( 0x18, PTR  , "VMT Classname"                  , "GL_Classname_"           );
	    VMTField vDynamicTable      = new VMTField( 0x20, PTR  , "VMT DynamicTable"               , "GL_DynamicTable_"        );
	    VMTField vMethodTable       = new VMTField( 0x28, PTR  , "VMT MethodTable"                , "GL_MethodTable_"         );
	    VMTField vFieldTable        = new VMTField( 0x30, PTR  , "VMT FieldTable"                 , "GL_FieldTable_"          );
	    VMTField vTypeInfo          = new VMTField( 0x38, PTR  , "VMT TypeInfo"                   , "GL_TypeInfo_"            );
	    VMTField vInitTable         = new VMTField( 0x40, PTR  , "VMT InitTable"                  , "GL_InitTable_"           );
	    VMTField vAutoTable         = new VMTField( 0x48, PTR  , "VMT AutoTable"                  , "GL_AutoTable_"           );
	    VMTField vIntfTable         = new VMTField( 0x50, PTR  , "VMT IntfTable"                  , "GL_IntfTable_"           );
	    VMTField vMsgStrPtr         = new VMTField( 0x58, PTR  , "VMT MsgStrPtr"                  , "GL_MsgStrPtr_"           );
	    VMTField vDestroy           = new VMTField( 0x60, PTR  , "VMT Destroy()"                  , "::Destroy"               );
	    VMTField vNewInstance       = new VMTField( 0x68, PTR  , "VMT NewInstance()"              , "::NewInstance"           );
	    VMTField vFreeInstance      = new VMTField( 0x70, PTR  , "VMT FreeInstance()"             , "::FreeInstance"          );
	    VMTField vSafeCallException = new VMTField( 0x78, PTR  , "VMT SafeCallException()"        , "::SafeCallException"     );
	    VMTField vDefaultHandler    = new VMTField( 0x80, PTR  , "VMT DefaultHandler()"           , "::DefaultHandler"        );
	    VMTField vAfterConstruction = new VMTField( 0x88, PTR  , "VMT AfterConstruction()"        , "::AfterConstruction"     );
	    VMTField vBeforeDestruction = new VMTField( 0x90, PTR  , "VMT BeforeDestruction()"        , "::BeforeDestruction"     );
	    VMTField vDefaultHandlerStr = new VMTField( 0x98, PTR  , "VMT DefaultHandlerStr()"        , "::DefaultHandlerStr"     );
	    VMTField vDispatch          = new VMTField( 0xA0, PTR  , "VMT Dispatch()"                 , "::Dispatch"              );
	    VMTField vDispatchStr       = new VMTField( 0xA8, PTR  , "VMT DispatchStr()"              , "::DispatchStr"           );
	    VMTField vEquals            = new VMTField( 0xB0, PTR  , "VMT Equals()"                   , "::Equals"                );
	    VMTField vGetHashCode       = new VMTField( 0xB8, PTR  , "VMT GetHashCode()"              , "::GetHashCode"           );
	    VMTField vToString          = new VMTField( 0xC0, PTR  , "VMT ToString()"                 , "::ToString"              );
	    ArrayList<VMTField> vClassFunctions = new ArrayList<>();

		VMT(Address addr) throws Exception {
			pWriter.println("-------------------start VMT ["+addr.toString("0x")+"]-------------------");
			vClassName.initValues(         addr, null );
			//pWriter.println( "VMT name: [" + vClassName.shortStr.len + "] '" + vClassName.shortStr.value + "'" );
			vInstanceSize.initValues(      addr, vClassName );
			vInstanceSize2.initValues(     addr, vClassName );
			vParent.initValues(            addr, vClassName );
			// the previous three calls need to happend after classname and before the rest of the table
			vDynamicTable.initValues(      addr, vClassName );
			vMethodTable.initValues(       addr, vClassName );
			vFieldTable.initValues(        addr, vClassName );
			vTypeInfo.initValues(          addr, vClassName );
			vInitTable.initValues(         addr, vClassName );
			vAutoTable.initValues(         addr, vClassName );
			vIntfTable.initValues(         addr, vClassName );
			vMsgStrPtr.initValues(         addr, vClassName );
			vDestroy.initValues(           addr, vClassName );
			vNewInstance.initValues(       addr, vClassName );
			vFreeInstance.initValues(      addr, vClassName );
			vSafeCallException.initValues( addr, vClassName );
			vDefaultHandler.initValues(    addr, vClassName );
			vAfterConstruction.initValues( addr, vClassName );
			vBeforeDestruction.initValues( addr, vClassName );
			vDefaultHandlerStr.initValues( addr, vClassName );
			vDispatch.initValues(          addr, vClassName );
			vDispatchStr.initValues(       addr, vClassName );
			vEquals.initValues(            addr, vClassName );
			vGetHashCode.initValues(       addr, vClassName );
			vToString.initValues(          addr, vClassName );

			vDestroy.createFunc(           vClassName );
			vNewInstance.createFunc(       vClassName );
			vFreeInstance.createFunc(      vClassName );
			vSafeCallException.createFunc( vClassName );
			vDefaultHandler.createFunc(    vClassName );
			vAfterConstruction.createFunc( vClassName );
			vBeforeDestruction.createFunc( vClassName );
			vDefaultHandlerStr.createFunc( vClassName );
			vDispatch.createFunc(          vClassName );
			vDispatchStr.createFunc(       vClassName );
			vEquals.createFunc(            vClassName );
			vGetHashCode.createFunc(       vClassName );
			vToString.createFunc(          vClassName );

			int funcNum = 0;
			long mPtrValue = -1;
			int mPtrOffset = vToString.offset;
			while( mPtrValue != 0 ){
				if( monitor.isCancelled() ){
					pWriter.println( vClassName.shortStr.value + " Canceled by monitor. In VMT func pointer loop");
					break;
				}
				funcNum++;
				mPtrOffset += 8;
				String funcExt = "::func" + funcNum;
				String comment = "Class func" + funcNum;
				VMTField funcField = new VMTField( mPtrOffset, PTR, comment, funcExt );
				funcField.initValues( addr, vClassName );
				mPtrValue = funcField.ptrAddr.getUnsignedOffset();
				funcField.createFunc( vClassName );
			}
			pWriter.println("-------------------end   VMT ["+addr.toString("0x")+"] (" + vClassName.shortStr.value + ")-------------------");
		}
	}

	@Override
	public void run() throws Exception {
		File inputFile  = new File( getProgramFile().getParentFile(), "AWH_VMT_addr.txt");
		File outputFile = new File( getProgramFile().getParentFile(), "AWH_VMT.txt");
		pWriter = new PrintWriter(new FileOutputStream(outputFile));
		try {
			addressFactory  = currentProgram.getAddressFactory();
			dataTypeManager = currentProgram.getDataTypeManager();
			functionManager = currentProgram.getFunctionManager();
			listing         = currentProgram.getListing();
			memory          = currentProgram.getMemory();
			symbolTable     = currentProgram.getSymbolTable();

			MemoryBlock dataBlock = memory.getBlock(".data");
			dataStart = dataBlock.getStart();
			dataEnd = dataBlock.getEnd();

			pWriter.println("Date: " + new Date(System.currentTimeMillis()) );
			pWriter.println("programFile:  " + getProgramFile().getAbsolutePath());
			pWriter.println("current addr: " + currentAddress.toString("0x"));
			pWriter.printf("name: %-20s 0x%-15s 0x%-15s\n", dataBlock.getName(), dataStart, dataEnd);

			Iterator<DataType> dti = dataTypeManager.getAllDataTypes();
			while (dti.hasNext()) {
				DataType dt = dti.next();
				String path = dt.getDataTypePath().getPath();
				//pWriter.println("DataType path: " + path);
				switch (path) {
					case "/byte":
						BYTE = dt;
						break;
					case "/word":
						WORD = dt;
						break;
					case "/dword":
						DWORD = dt;
						break;
					case "/qword":
						QWORD = dt;
						break;
					case "/pointer":
						PTR = dt;
						break;
					case "/TerminatedCString":
						CSTRING = dt;
						break;
				}
			}
			if (BYTE == null) {
				pWriter.println("DataType [BYTE   ] not found.");
				throw new Exception();
			}
			if (WORD == null) {
				pWriter.println("DataType [WORD   ] not found.");
				throw new Exception();
			}
			if (DWORD == null) {
				pWriter.println("DataType [DWORD  ] not found.");
				throw new Exception();
			}
			if (QWORD == null) {
				pWriter.println("DataType [QWORD  ] not found.");
				throw new Exception();
			}
			if (PTR == null) {
				pWriter.println("DataType [PTR    ] not found.");
				throw new Exception();
			}
			if (CSTRING == null) {
				pWriter.println("DataType [CSTRING] not found.");
				throw new Exception();
			}
			if( inputFile.exists() ){
				FileReader reader = new FileReader(inputFile);
				BufferedReader br = new BufferedReader(reader);
				int prefixSize = "/* Symbol_ADDR_".length();
				pWriter.println("prefixSize [" + prefixSize + "]");
				br.lines().forEach( line -> {
					if( !line.contains("PTR_GL_VMT_") && line.contains("GL_VMT_") ) {
						String addrLine1 = line.substring(prefixSize);
						String addrLine = addrLine1.substring(0, 11).trim();
						pWriter.println("after  [" + addrLine.length() + "][" + addrLine + "][" + line + "]");
						Address vmtAddr = currentProgram.getAddressFactory().getAddress(addrLine.trim());
						try {
							VMT vmt = new VMT(vmtAddr);
						} catch (Exception e) {
							e.printStackTrace( pWriter );
						}
					}
				});
			} else {
				VMT vmt = new VMT(currentAddress);
			}
		} catch (Exception e ) {
			e.printStackTrace( pWriter );
		} finally {
			pWriter.close();
		}
	}

	void doit() throws Exception {
		File outputFile = new File( getProgramFile().getParentFile(), "AWH_VMT.txt");
		PrintWriter pWriter = new PrintWriter(new FileOutputStream(outputFile));
		//println( "currentDir:      " + new File(".").getAbsolutePath() );
		//println( "outputFile:      " + outputFile.getAbsolutePath() );
		//println( "sourceFile path: " + sourceFile.getAbsolutePath() );
		println( "programFile:     " + getProgramFile().getAbsolutePath() );

		MemoryBlock dataBlock = currentProgram.getMemory().getBlock(".data");
		Address dataStart = dataBlock.getStart();
		Address dataEnd   = dataBlock.getEnd();
		pWriter.printf( "name: %-20s 0x%-15s 0x%-15s\n", dataBlock.getName(), dataStart, dataEnd );

		SymbolTable symbolTable = currentProgram.getSymbolTable();
		SymbolIterator symbolIterator = symbolTable.getSymbolIterator();
		while( symbolIterator.hasNext() ){
			Symbol symbol = symbolIterator.next();
			if(symbol.getName().startsWith("GL_VMT_TObject")) {
				Address addr = symbol.getAddress();
				VMT vmt = new VMT( addr );
				int refCount = currentProgram.getReferenceManager().getReferenceCountTo(addr);
				pWriter.printf( "name: %-20s [%d] 0x%-15s\n", symbol.getName(), refCount, addr );
				ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(addr);
				int i = 1;
				while( refs.hasNext() ){
					Reference ref = refs.next();
					Address fromAddr = ref.getFromAddress();
					if( dataStart.subtract(fromAddr) <= 0 && dataEnd.subtract(fromAddr) >= 0 ) {
						pWriter.printf( "data:  %03d/%03d 0x%-20s \n", i++, refCount, fromAddr );
					} else {
						pWriter.printf( "other: %03d/%03d 0x%-20s \n", i++, refCount, fromAddr );
					}
				}
				//pWriter.println("Label: "+ addr.toString("0x") + "["+ refCount +"]" + " => " + symbol.getName() );
			}
		}
		pWriter.close();
	}
}
