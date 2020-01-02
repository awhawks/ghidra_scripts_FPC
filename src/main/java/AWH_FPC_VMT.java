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
// Labels a VMT table based on its classname string
//@category AWH
//@keybinding shift ctrl V
//@menupath AWH.VMT
//@toolbar vmt.png

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;


import java.io.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;

public class AWH_FPC_VMT extends GhidraScript {
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

	void init() throws Exception {
		addressFactory  = currentProgram.getAddressFactory();
		dataTypeManager = currentProgram.getDataTypeManager();
		functionManager = currentProgram.getFunctionManager();
		listing         = currentProgram.getListing();
		memory          = currentProgram.getMemory();
		symbolTable     = currentProgram.getSymbolTable();

		MemoryBlock dataBlock = memory.getBlock(".data");
		dataStart = dataBlock.getStart();
		dataEnd = dataBlock.getEnd();

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
		pWriter.println("Date: " + new Date(System.currentTimeMillis()) );
		pWriter.println("programFile:  " + getProgramFile().getAbsolutePath());
		pWriter.println("current addr: " + currentAddress.toString("0x"));
		pWriter.printf("name: %-20s 0x%-15s 0x%-15s\n", dataBlock.getName(), dataStart, dataEnd);

	}

	@Override
	public void run() throws Exception {
		File inputFile  = new File( getProgramFile().getParentFile(), "AWH_VMT_addr.txt");
		File outputFile = new File( getProgramFile().getParentFile(), "AWH_VMT_out.txt");
		pWriter = new PrintWriter(new FileOutputStream(outputFile));
		try {
			init();
			ArrayList<VMT> vmtList = new ArrayList<>();
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
						Address lineAddr = currentProgram.getAddressFactory().getAddress(addrLine.trim());
						Address vmtAddr  = lineAddr.add(0x0);
						if( line.contains("_xxx")){
							vmtAddr = lineAddr.subtract(0x10);
						}
						try {
							vmtList.add( new VMT(vmtAddr) );
						} catch (Exception e) {
							e.printStackTrace( pWriter );
						}
					}
				});
			} else {
				vmtList.add( new VMT(currentAddress) );
			}

		} catch (Exception e ) {
			e.printStackTrace( pWriter );
		} finally {
			pWriter.close();
		}
	}


	class VMT {
		VMTField vInstanceSize;
		VMTField vInstanceSize2;
		VMTField vParent;
		VMTField vClassName;
		VMTField vDynamicTable;
		VMTField vMethodTable;
		VMTField vFieldTable;
		VMTField vTypeInfo;
		VMTField vInitTable;
		VMTField vAutoTable;
		VMTField vIntfTable;
		VMTField vMsgStrPtr;
		VMTField vDestroy;
		VMTField vNewInstance;
		VMTField vFreeInstance;
		VMTField vSafeCallException;
		VMTField vDefaultHandler;
		VMTField vAfterConstruction;
		VMTField vBeforeDestruction;
		VMTField vDefaultHandlerStr;
		VMTField vDispatch;
		VMTField vDispatchStr;
		VMTField vEquals;
		VMTField vGetHashCode;
		VMTField vToString;
		ArrayList<VMTField> vClassFunctions = new ArrayList<>();

		VMT(Address addr) throws Exception {
			Address parentPtr    = addr.add( 0x10 );
			Data parentData = DataUtilities.getDataAtAddress(currentProgram, parentPtr);
			if( parentData != null ) {
				CodeUnit pcu = listing.getCodeUnitAt(parentPtr);

			}

			Address classnamePtr = addr.add( 0x19 );
			pWriter.println("-------------------start VMT ["+addr.toString("0x")+"]-------------------");
			// classname is parsed first to get classname
			// parent    is parsed next to populate parent fucntions before current one
			vClassName         = new VMTField( addr, null, 0x18, PTR  , "VMT Classname"                  , "GL_Classname_"           );
			String className = vClassName.className;
			//pWriter.println( "VMT name: [" + vClassName.shortStr.len + "] '" + vClassName.shortStr.value + "'" );
			boolean alreadyParsed = false;
			// print out symbols found at this VMT address
			for( Symbol symbol : symbolTable.getSymbols(addr) ){
				String name = symbol.getName();
				if( name.equals( className ) ){
					alreadyParsed = true;
				}
				pWriter.println( className + " Found symbol at " + addr.toString("0x" ) + ": " + name );
			}
			if( !alreadyParsed ) {
				vParent            = new VMTField(addr, className, 0x10, PTR,   "VMT Parent",                      null);
				vInstanceSize      = new VMTField(addr, className, 0x00, QWORD, "VMT Instance Size",               "GL_InstanceSize_");
				vInstanceSize2     = new VMTField(addr, className, 0x08, QWORD, "VMT Instance Size 2s Complement", "GL_InstanceSize_2scomp_");
				vDynamicTable      = new VMTField(addr, className, 0x20, PTR,   "VMT DynamicTable",                "GL_DynamicTable_");
				vMethodTable       = new VMTField(addr, className, 0x28, PTR,   "VMT MethodTable",                 "GL_MethodTable_");
				vFieldTable        = new VMTField(addr, className, 0x30, PTR,   "VMT FieldTable",                  "GL_FieldTable_");
				vTypeInfo          = new VMTField(addr, className, 0x38, PTR,   "VMT TypeInfo",                    "GL_TypeInfo_");
				vInitTable         = new VMTField(addr, className, 0x40, PTR,   "VMT InitTable",                   "GL_InitTable_");
				vAutoTable         = new VMTField(addr, className, 0x48, PTR,   "VMT AutoTable",                   "GL_AutoTable_");
				vIntfTable         = new VMTField(addr, className, 0x50, PTR,   "VMT IntfTable",                   "GL_IntfTable_");
				vMsgStrPtr         = new VMTField(addr, className, 0x58, PTR,   "VMT MsgStrPtr",                   "GL_MsgStrPtr_");
				vDestroy           = new VMTField(addr, className, 0x60, PTR,   "VMT Destroy()",                   "Destroy");
				vNewInstance       = new VMTField(addr, className, 0x68, PTR,   "VMT NewInstance()",               "NewInstance");
				vFreeInstance      = new VMTField(addr, className, 0x70, PTR,   "VMT FreeInstance()",              "FreeInstance");
				vSafeCallException = new VMTField(addr, className, 0x78, PTR,   "VMT SafeCallException()",         "SafeCallException");
				vDefaultHandler    = new VMTField(addr, className, 0x80, PTR,   "VMT DefaultHandler()",            "DefaultHandler");
				vAfterConstruction = new VMTField(addr, className, 0x88, PTR,   "VMT AfterConstruction()",         "AfterConstruction");
				vBeforeDestruction = new VMTField(addr, className, 0x90, PTR,   "VMT BeforeDestruction()",         "BeforeDestruction");
				vDefaultHandlerStr = new VMTField(addr, className, 0x98, PTR,   "VMT DefaultHandlerStr()",         "DefaultHandlerStr");
				vDispatch          = new VMTField(addr, className, 0xA0, PTR,   "VMT Dispatch()",                  "Dispatch");
				vDispatchStr       = new VMTField(addr, className, 0xA8, PTR,   "VMT DispatchStr()",               "DispatchStr");
				vEquals            = new VMTField(addr, className, 0xB0, PTR,   "VMT Equals()",                    "Equals");
				vGetHashCode       = new VMTField(addr, className, 0xB8, PTR,   "VMT GetHashCode()",               "GetHashCode");
				vToString          = new VMTField(addr, className, 0xC0, PTR,   "VMT ToString()",                  "ToString");

				int funcNum = 0;
				long mPtrValue = -1;
				int mPtrOffset = vToString.offset;
				while (mPtrValue != 0) {
					if (monitor.isCancelled()) {
						pWriter.println( className + " Canceled by monitor. In VMT func pointer loop");
						break;
					}
					funcNum++;
					mPtrOffset += 8;
					String funcExt = "func" + funcNum;
					String comment = "Class func" + funcNum;
					VMTField funcField = new VMTField(addr, className, mPtrOffset, PTR, comment, funcExt);
					mPtrValue = funcField.ptrAddr.getUnsignedOffset();
				}
			} else {
				pWriter.println("Already parsed " + vClassName.className );
			}
			pWriter.println("-------------------end   VMT ["+addr.toString("0x")+"] (" + className + ")-------------------");
		}
	}

	class VMTField {
		Address  vmtStartAddr;
		Address  fieldAddr;
		Address  ptrAddr;
		//
		String   className;
		int      offset;
		DataType dataType;
		String   comment;
		String   ptrPrefixSuffix;
		//
		int         qwordValue;
		VMT         parent;

		VMTField( Address arg_vmtStartAddr, String arg_classname, int arg_offset, DataType arg_dataType, String arg_comment, String arg_ptrPrefixSuffix ) throws Exception {
			vmtStartAddr    = arg_vmtStartAddr;
			if( arg_classname != null ) {
				className = arg_classname;
			}
			offset          = arg_offset;
			dataType        = arg_dataType;
			comment         = arg_comment;
			ptrPrefixSuffix = arg_ptrPrefixSuffix;
			//pWriter.printf("VMT Field:      %03d %-20s %-25s %-40s\n", offset, dataType.getPathName(), ptrNamePrefix, comment);
			fieldAddr = vmtStartAddr.add(offset);
			clearListing(fieldAddr);
			Data data = createData(fieldAddr, dataType );
			listing.getCodeUnitAt(fieldAddr).setComment( CodeUnit.EOL_COMMENT, comment );
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
						ShortString shortStr = new ShortString(ptrAddr);
						className = shortStr.value;
						// set label for VMT table
						String vmtLabel  = "GL_VMT_" + className;
						boolean skipCreateLabel = false;
						Symbol vmtSymbol = null;
						if( symbolTable.hasSymbol(vmtStartAddr) ) {
							for( Symbol symbol : symbolTable.getSymbols(vmtStartAddr) ) {
								if( symbol.getName().equals(vmtLabel) ) {
									vmtSymbol = symbol;
									skipCreateLabel = true;
								}
							}
						}
						if( !skipCreateLabel ) {
							vmtSymbol = createLabel(vmtStartAddr, vmtLabel, true);
							symbolTable.createClass( currentProgram.getGlobalNamespace(), className, SourceType.USER_DEFINED);
						}
						int refCount = currentProgram.getReferenceManager().getReferenceCountTo(vmtStartAddr);
						pWriter.printf( "%s VMT name:  %-20s [%03d] 0x%-15s 0x%-15s\n", className, vmtSymbol.getName(), refCount, vmtStartAddr, fieldAddr);
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
							String dataFieldLabel = ptrPrefixSuffix + className;
							Symbol dataFieldSymbol = createLabel(ptrAddr, dataFieldLabel, true);
							pWriter.printf("%s VMT field init: %-20s       0x%-15s\n", className, dataFieldSymbol.getName(), ptrAddr);
						}
						break;
					default: // class functions
						if( ptrAddr.getUnsignedOffset() != 0 ) {
							fieldAddr = vmtStartAddr.add(offset);
							pWriter.printf("%s VMT field init:                            0x%-15s\n", className, ptrAddr);
							createFunc();
						}
						break;
				}
			}
		}

		public void createFunc() throws Exception {
			if( ptrAddr.getUnsignedOffset() != 0 ) {
				String funcName = className + "::" + ptrPrefixSuffix;
				pWriter.println(funcName + " Func start:           " + fieldAddr.toString("0x") + " => " + ptrAddr.toString("0x"));
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
					existingFunc = getFunctionAt(ptrAddr);
					if( existingFunc == null ) {
						pWriter.println(funcName + " Creating Func at:     " + ptrAddr.toString("0x"));

						Function newFunc = createFunction(ptrAddr, ptrPrefixSuffix); // TODO
						if (newFunc == null) {
							newFunc = listing.getFunctionAt(ptrAddr);
							if (newFunc == null) {
								pWriter.println(funcName + " Error: null pointer for function at " + ptrAddr.toString("0x"));
								throw new Exception();
							} else {
								pWriter.println(funcName + " Func:                 " + ptrAddr.toString("0x") + " with name: " + newFunc.getName());
							}
						} else {
							Namespace ns = symbolTable.getNamespace(className, currentProgram.getGlobalNamespace());
							newFunc.setParentNamespace(ns);
							pWriter.println(funcName + " Func:                 " + ptrAddr.toString("0x") + " with name: " + newFunc.getName());
						}
						analyzeChanges(currentProgram);
					}
				} else {
					// fuction exist so check name
					String existingName = existingFunc.getName(true);
					boolean alreadyRenamed = existingName.contains("::");
					if (alreadyRenamed) {
						pWriter.println(funcName + " Func already renamed: " + ptrAddr.toString("0x") + " not done existing name [" + existingName + "] would have done " + existingFunc.getName() + " => " + funcName);
					} else {
						if (!existingFunc.getName(true).equals(funcName)) {
							pWriter.print(funcName + " Func renaming:        " + ptrAddr.toString("0x") + " with name: " + existingFunc.getName(true));
							existingFunc.setName(funcName, SourceType.USER_DEFINED);
							pWriter.println( " => " + existingFunc.getName(true));
							analyzeChanges(currentProgram);
						}
					}
				}
				pWriter.println(funcName + " Func end:             " + fieldAddr.toString("0x") + " => " + ptrAddr.toString("0x"));
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

}
