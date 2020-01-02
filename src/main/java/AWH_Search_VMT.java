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
// Search for VMT table entries
//@category AWH
//@menupath AWH.Search_VMT
//@toolbar search.png

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;

public class AWH_Search_VMT extends GhidraScript {
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
	private Address     textStart;
	private Address     textEnd;
	private PrintWriter pWriter;

	private byte[] stringToBytes(String str) {
		byte[] val = new byte[str.length() / 2];
		for (int i = 0; i < val.length; i++) {
			int index = i * 2;
			int j = Integer.parseInt(str.substring(index, index + 2), 16);
			val[i] = (byte) j;
		}
		return val;
	}

	private void dualPrint( String msg ){
		print(msg);
		pWriter.print( msg );
		pWriter.flush();
	}

	private void dualPrintln( String msg ){
		println(msg);
		pWriter.println( msg );
		pWriter.flush();
	}

	void init() throws Exception {
		addressFactory  = currentProgram.getAddressFactory();
		dataTypeManager = currentProgram.getDataTypeManager();
		functionManager = currentProgram.getFunctionManager();
		listing         = currentProgram.getListing();
		memory          = currentProgram.getMemory();
		symbolTable     = currentProgram.getSymbolTable();

		MemoryBlock dataBlock = memory.getBlock(".data");
		dataStart = dataBlock.getStart();
		dataEnd   = dataBlock.getEnd();

		MemoryBlock textBlock = memory.getBlock(".text");
		textStart = textBlock.getStart();
		textEnd   = textBlock.getEnd();

		Iterator<DataType> dti = dataTypeManager.getAllDataTypes();
		while (dti.hasNext()) {
			if (monitor.isCancelled()) {
				break;
			}
			DataType dt = dti.next();
			String path = dt.getDataTypePath().getPath();
			//dualPrintln("DataType path: " + path);
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
			dualPrintln("DataType [BYTE   ] not found.");
			throw new Exception();
		}
		if (WORD == null) {
			dualPrintln("DataType [WORD   ] not found.");
			throw new Exception();
		}
		if (DWORD == null) {
			dualPrintln("DataType [DWORD  ] not found.");
			throw new Exception();
		}
		if (QWORD == null) {
			dualPrintln("DataType [QWORD  ] not found.");
			throw new Exception();
		}
		if (PTR == null) {
			dualPrintln("DataType [PTR    ] not found.");
			throw new Exception();
		}
		if (CSTRING == null) {
			dualPrintln("DataType [CSTRING] not found.");
			throw new Exception();
		}
		dualPrintln("Date: " + new Date(System.currentTimeMillis()) );
		dualPrintln("programFile:  " + getProgramFile().getAbsolutePath());
		dualPrintln("current addr: " + currentAddress.toString("0x"));
		dualPrintln(String.format("name: %-20s 0x%-15s 0x%-15s", dataBlock.getName(), dataStart, dataEnd));
	}

	@Override
	protected void run() throws Exception {
		File outputFile = new File( getProgramFile().getParentFile(), "AWH_VMT_search.txt");
		pWriter = new PrintWriter(new FileOutputStream(outputFile));
		init();
		try {
			Memory memory = currentProgram.getMemory();
			SymbolTable symbolTable = currentProgram.getSymbolTable();

			MemoryBlock dataBlock = memory.getBlock(".data");
			Address dataStart = dataBlock.getStart();
			Address dataEnd = dataBlock.getEnd();

			dualPrintln("current    addr: " + currentAddress.toString("0x"));
			dualPrintln("data start addr: " + dataStart.toString("0x"));
			dualPrintln("data end   addr: " + dataEnd.toString("0x"));

			Address start = dataStart;
			byte[] search = stringToBytes("FFFFFFFFFFFF");
			byte[] mask = stringToBytes("FFFFFFFFFFFF");
			while (start.getUnsignedOffset() < dataEnd.getUnsignedOffset()) {
				if (monitor.isCancelled()) {
					break;
				}
				Address foundBytes = memory.findBytes(start, dataEnd, search, mask, true, monitor);
				if (foundBytes != null) {
					// find end FF
					int endOffset = 0;
					int cb = 0xFF;
					while (cb == 0xFF) {
						if (monitor.isCancelled()) {
							break;
						}
						endOffset++;
						cb = ((int) memory.getByte(foundBytes.add(endOffset))) & 0xFF;
					}
					Address vmtAddr = foundBytes.add(endOffset).subtract(0x10);
					boolean isValidVMT = isAVMT(vmtAddr);
					if( isValidVMT ){
						Symbol[] symbols = symbolTable.getSymbols(vmtAddr);
						String syms = "";
						for (Symbol symbol : symbols) {
							syms += " [" + symbol.getName(true) + "]";
						}
						dualPrintln(String.format("[%s - %s][%s]found: %s VMT: %s  %s",
								dataStart.toString("0x"),
								dataEnd.toString("0x"),
								start.toString("0x"),
								foundBytes.toString("0x"),
								vmtAddr.toString("0x"),
								syms
						));
						new SVMT(vmtAddr);
					}
					start = vmtAddr.add(0xC8);
				} else {
					dualPrintln(String.format("[%s - %s][%s] Did not find in range",
							dataStart.toString("0x"),
							dataEnd.toString("0x"),
							start.toString("0x")
					));
					start = dataEnd;
				}
			}
		} catch (Exception e){
			pWriter.write( e.getMessage() );
			e.printStackTrace(pWriter);
			throw e;
		} finally {
			pWriter.close();
		}
	}

	private boolean isInDataSegment(long value){
		boolean valid = false;
		if( value >= dataStart.getUnsignedOffset() && value <= dataEnd.getUnsignedOffset() ){
			valid = true;
		}
		return valid;
	}

	private boolean isInTextSegment(long value){
		boolean valid = false;
		if( value >= textStart.getUnsignedOffset() && value <= textEnd.getUnsignedOffset() ){
			valid = true;
		}
		return valid;
	}

	private boolean isAVMT(Address vmtAddr) throws Exception {
		long valOfInstanceSize      = memory.getLong( vmtAddr.add(0x00) );
		long valOfInstanceSize2     = memory.getLong( vmtAddr.add(0x08) );
		long valOfParent            = memory.getLong( vmtAddr.add(0x10) );
		long valOfClassName         = memory.getLong( vmtAddr.add(0x18) );
		long valOfTypeInfo          = memory.getLong( vmtAddr.add(0x38) );
		long valOfDestroy           = memory.getLong( vmtAddr.add(0x60) );
		long valOfNewInstance       = memory.getLong( vmtAddr.add(0x68) );
		long valOfFreeInstance      = memory.getLong( vmtAddr.add(0x70) );
		long valOfSafeCallException = memory.getLong( vmtAddr.add(0x78) );
		long valOfDefaultHandler    = memory.getLong( vmtAddr.add(0x80) );
		long valOfAfterConstruction = memory.getLong( vmtAddr.add(0x88) );
		long valOfBeforeDestruction = memory.getLong( vmtAddr.add(0x90) );
		long valOfDefaultHandlerStr = memory.getLong( vmtAddr.add(0x98) );
		long valOfDispatch          = memory.getLong( vmtAddr.add(0xA0) );
		long valOfDispatchStr       = memory.getLong( vmtAddr.add(0xA8) );
		long valOfEquals            = memory.getLong( vmtAddr.add(0xB0) );
		long valOfGetHashCode       = memory.getLong( vmtAddr.add(0xB8) );
		long valOfToString          = memory.getLong( vmtAddr.add(0xC0) );

		boolean valid = false;
		if( valOfInstanceSize      != 0 &&
				valOfInstanceSize2     != 0 &&
				valOfClassName         != 0 &&
				valOfTypeInfo          != 0 &&
				valOfDestroy           != 0 &&
				valOfNewInstance       != 0 &&
				valOfFreeInstance      != 0 &&
				valOfSafeCallException != 0 &&
				valOfDefaultHandler    != 0 &&
				valOfAfterConstruction != 0 &&
				valOfBeforeDestruction != 0 &&
				valOfDefaultHandlerStr != 0 &&
				valOfDispatch          != 0 &&
				valOfDispatchStr       != 0 &&
				valOfEquals            != 0 &&
				valOfGetHashCode       != 0 &&
				valOfToString          != 0
		) {
			if( (valOfParent == 0 || isInDataSegment( valOfParent ) ) &&
					isInDataSegment( valOfClassName ) &&
					isInDataSegment( valOfTypeInfo ) ){
				if( isInTextSegment( valOfDestroy           ) &&
						isInTextSegment( valOfNewInstance       ) &&
						isInTextSegment( valOfFreeInstance      ) &&
						isInTextSegment( valOfSafeCallException ) &&
						isInTextSegment( valOfDefaultHandler    ) &&
						isInTextSegment( valOfAfterConstruction ) &&
						isInTextSegment( valOfBeforeDestruction ) &&
						isInTextSegment( valOfDefaultHandlerStr ) &&
						isInTextSegment( valOfDispatch          ) &&
						isInTextSegment( valOfDispatchStr       ) &&
						isInTextSegment( valOfEquals            ) &&
						isInTextSegment( valOfGetHashCode       ) &&
						isInTextSegment( valOfToString          ) ) {
					valid = true;
				} else {
					dualPrintln(String.format("#### %s has non-text locations in one of VMT functions", vmtAddr.toString("0x")));
				}
			} else {
				dualPrintln(String.format("#### %s has non-data locations in one of parent/classname/typeInfo VMT parts", vmtAddr.toString("0x")));
			}
		} else {
			dualPrintln(String.format("#### %s has null pointers in needed VMT parts", vmtAddr.toString("0x")));
		}
		return valid;
	}

	class SVMT {
		SVMTField vInstanceSize;
		SVMTField vInstanceSize2;
		SVMTField vParent;
		SVMTField vClassName;
		SVMTField vDynamicTable;
		SVMTField vMethodTable;
		SVMTField vFieldTable;
		SVMTField vTypeInfo;
		SVMTField vInitTable;
		SVMTField vAutoTable;
		SVMTField vIntfTable;
		SVMTField vMsgStrPtr;
		SVMTField vDestroy;
		SVMTField vNewInstance;
		SVMTField vFreeInstance;
		SVMTField vSafeCallException;
		SVMTField vDefaultHandler;
		SVMTField vAfterConstruction;
		SVMTField vBeforeDestruction;
		SVMTField vDefaultHandlerStr;
		SVMTField vDispatch;
		SVMTField vDispatchStr;
		SVMTField vEquals;
		SVMTField vGetHashCode;
		SVMTField vToString;
		ArrayList<SVMTField> vClassFunctions = new ArrayList<>();

		SVMT(Address addr) throws Exception {
			dualPrintln("-------------------start SVMT ["+addr.toString("0x")+"]-------------------");
			// classname is parsed first to get classname
			// parent    is parsed next to populate parent fucntions before current one
			vClassName         = new SVMTField( addr, null, 0x18, PTR  , "VMT Classname"                  , "GL_Classname_"           );
			String className = vClassName.className;
			dualPrintln( "VMT name: [" + className.length() + "] '" + className + "'" );
			boolean alreadyParsed = false;
			// print out symbols found at this VMT address
			for( Symbol symbol : symbolTable.getSymbols(addr) ){
				String name = symbol.getName();
				if( name.equals( className ) ){
					alreadyParsed = true;
				}
				dualPrintln( className + " Found symbol at " + addr.toString("0x" ) + ": " + name );
			}
			if( !alreadyParsed ) {
				vParent            = new SVMTField(addr, className, 0x10, PTR,   "VMT Parent",                      null);
				vInstanceSize      = new SVMTField(addr, className, 0x00, QWORD, "VMT Instance Size",               "GL_InstanceSize_");
				vInstanceSize2     = new SVMTField(addr, className, 0x08, QWORD, "VMT Instance Size 2s Complement", "GL_InstanceSize_2scomp_");
				vDynamicTable      = new SVMTField(addr, className, 0x20, PTR,   "VMT DynamicTable",                "GL_DynamicTable_");
				vMethodTable       = new SVMTField(addr, className, 0x28, PTR,   "VMT MethodTable",                 "GL_MethodTable_");
				vFieldTable        = new SVMTField(addr, className, 0x30, PTR,   "VMT FieldTable",                  "GL_FieldTable_");
				vTypeInfo          = new SVMTField(addr, className, 0x38, PTR,   "VMT TypeInfo",                    "GL_TypeInfo_");
				vInitTable         = new SVMTField(addr, className, 0x40, PTR,   "VMT InitTable",                   "GL_InitTable_");
				vAutoTable         = new SVMTField(addr, className, 0x48, PTR,   "VMT AutoTable",                   "GL_AutoTable_");
				vIntfTable         = new SVMTField(addr, className, 0x50, PTR,   "VMT IntfTable",                   "GL_IntfTable_");
				vMsgStrPtr         = new SVMTField(addr, className, 0x58, PTR,   "VMT MsgStrPtr",                   "GL_MsgStrPtr_");
				vDestroy           = new SVMTField(addr, className, 0x60, PTR,   "VMT Destroy()",                   "Destroy");
				vNewInstance       = new SVMTField(addr, className, 0x68, PTR,   "VMT NewInstance()",               "NewInstance");
				vFreeInstance      = new SVMTField(addr, className, 0x70, PTR,   "VMT FreeInstance()",              "FreeInstance");
				vSafeCallException = new SVMTField(addr, className, 0x78, PTR,   "VMT SafeCallException()",         "SafeCallException");
				vDefaultHandler    = new SVMTField(addr, className, 0x80, PTR,   "VMT DefaultHandler()",            "DefaultHandler");
				vAfterConstruction = new SVMTField(addr, className, 0x88, PTR,   "VMT AfterConstruction()",         "AfterConstruction");
				vBeforeDestruction = new SVMTField(addr, className, 0x90, PTR,   "VMT BeforeDestruction()",         "BeforeDestruction");
				vDefaultHandlerStr = new SVMTField(addr, className, 0x98, PTR,   "VMT DefaultHandlerStr()",         "DefaultHandlerStr");
				vDispatch          = new SVMTField(addr, className, 0xA0, PTR,   "VMT Dispatch()",                  "Dispatch");
				vDispatchStr       = new SVMTField(addr, className, 0xA8, PTR,   "VMT DispatchStr()",               "DispatchStr");
				vEquals            = new SVMTField(addr, className, 0xB0, PTR,   "VMT Equals()",                    "Equals");
				vGetHashCode       = new SVMTField(addr, className, 0xB8, PTR,   "VMT GetHashCode()",               "GetHashCode");
				vToString          = new SVMTField(addr, className, 0xC0, PTR,   "VMT ToString()",                  "ToString");

				int funcNum = 0;
				long mPtrValue = -1;
				int mPtrOffset = vToString.offset;
				while (mPtrValue != 0) {
					if (monitor.isCancelled()) {
						dualPrintln( className + " Canceled by monitor. In VMT func pointer loop");
						break;
					}
					funcNum++;
					mPtrOffset += 8;
					String funcExt = "func" + funcNum;
					String comment = "Class func" + funcNum;
					SVMTField funcField = new SVMTField(addr, className, mPtrOffset, PTR, comment, funcExt);
					mPtrValue = funcField.ptrAddr.getUnsignedOffset();
				}
			} else {
				dualPrintln("Already parsed " + vClassName.className );
			}
			analyzeChanges(currentProgram);
			dualPrintln("-------------------end   SVMT ["+addr.toString("0x")+"] (" + className + ")-------------------");
		}
	}

	class SVMTField {
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
		SVMT        parent;

		SVMTField( Address arg_vmtStartAddr, String arg_classname, int arg_offset, DataType arg_dataType, String arg_comment, String arg_ptrPrefixSuffix ) throws Exception {
			//dualPrintln("-------------------start SVMTField ["+arg_vmtStartAddr.toString("0x")+"](" + className + ")[" + arg_offset + "][" + arg_ptrPrefixSuffix + "][" + arg_comment + "]-------------------");
			vmtStartAddr    = arg_vmtStartAddr;
			if( arg_classname != null ) {
				className = arg_classname;
			}
			offset          = arg_offset;
			dataType        = arg_dataType;
			comment         = arg_comment;
			ptrPrefixSuffix = arg_ptrPrefixSuffix;
			//dualPrintln(String.format("VMT Field:      %03d %-20s %-25s %-40s", offset, dataType.getPathName(), ptrPrefixSuffix, comment));
			fieldAddr = vmtStartAddr.add(offset);
			int dtLen = dataType.getLength();
			for( int i=0; i<dtLen; i++) {
				clearListing( fieldAddr.add(i) );
			}
			Data data = createData(fieldAddr, dataType );
			listing.getCodeUnitAt(fieldAddr).setComment( CodeUnit.EOL_COMMENT, comment );
			if (QWORD.equals(dataType)) {
				qwordValue = (int) ((Scalar) data.getValue()).getValue();
			} else if (PTR.equals(dataType)) {
				ptrAddr = (Address) data.getValue();
				switch( offset ){
					case 0x00: // start of vmt and Instance Size 1
						break;
					case 0x10: // Parent VMT
						if( ptrAddr.getUnsignedOffset() != 0 ) {
							parent = new SVMT(ptrAddr);
						} else {
							parent = null;
						}
						break;
					case 0x18: // Classname
						SShortString shortStr = new SShortString(ptrAddr);
						className = shortStr.value;
						// set label for VMT table
						String vmtLabel  = "GL_VMT_" + className;
						boolean skipCreateLabel = false;
						Symbol vmtSymbol = null;
						if( symbolTable.hasSymbol(vmtStartAddr) ) {
							for( Symbol symbol : symbolTable.getSymbols(vmtStartAddr) ) {
								if( symbol.getName().startsWith(vmtLabel) ) {
									vmtSymbol = symbol;
									skipCreateLabel = true;
								}
							}
						}
						if( !skipCreateLabel ) {
							int extNum = 1;
							boolean found = true;
							String ext = "";
							while( found ) {
								if (monitor.isCancelled()) {
									break;
								}
								String searchLabel = "GL_VMT_" + shortStr.value + ext;
								found = symbolTable.getSymbols( searchLabel ).hasNext();
								if (found) {
									dualPrintln("#### found existing before label:     "+ searchLabel );
									dualPrintln("#### found existing before classname: "+ className );
									dualPrintln("#### found existing before vmtLabel:  "+ vmtLabel );
									extNum++;
									ext = Integer.toString(extNum);
									className = shortStr.value + ext;
									vmtLabel = "GL_VMT_" + className;
									dualPrintln("#### found existing after classname: "+ className );
									dualPrintln("#### found existing after vmtLabel:  "+ vmtLabel );
								}
							}
							vmtSymbol = createLabel(vmtStartAddr, vmtLabel, true);
							symbolTable.createClass( currentProgram.getGlobalNamespace(), className, SourceType.USER_DEFINED);
						}
						int refCount = currentProgram.getReferenceManager().getReferenceCountTo(vmtStartAddr);
						dualPrint( String.format("%s VMT name:  %-20s [%03d] 0x%-15s 0x%-15s", className, vmtSymbol.getName(), refCount, vmtStartAddr, fieldAddr));
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
							boolean makePrimary = true;
							for( Symbol symbol : symbolTable.getSymbols(ptrAddr) ) {
								if( symbol.getName().startsWith( ptrPrefixSuffix)) {
									makePrimary = false;
								}
							}
							String dataFieldLabel = ptrPrefixSuffix + className;
							Symbol dataFieldSymbol = createLabel(ptrAddr, dataFieldLabel, makePrimary);
							dualPrintln( String.format("%s VMT field init: %-20s       0x%-15s\n", className, dataFieldSymbol.getName(), ptrAddr));
						}
						break;
					default: // class functions
						if( ptrAddr.getUnsignedOffset() != 0 ) {
							fieldAddr = vmtStartAddr.add(offset);
							//dualPrintln( String.format("%s VMT field init:                            0x%-15s\n", className, ptrAddr));
							if( ptrAddr.getUnsignedOffset() >= textStart.getUnsignedOffset() && ptrAddr.getUnsignedOffset() < textEnd.getUnsignedOffset() ) {
								createFunc();
							} else {
								dualPrintln("#### Error creating Func at:           " + ptrAddr.toString("0x") + " since it's not in text area. textStart: " + textStart.toString("0x") + " textEnd: " + textEnd.toString("0x"));
							}
						}
						break;
				}
			}
			//dualPrintln("-------------------end   SVMTField ["+arg_vmtStartAddr.toString("0x")+"](" + className + ")[" + arg_offset + "][" + arg_ptrPrefixSuffix + "][" + arg_comment + "]-------------------");
		}

		public void createFunc() throws Exception {
			if( ptrAddr.getUnsignedOffset() != 0 ) {
				String funcName = className + "::" + ptrPrefixSuffix;
				dualPrintln(funcName + " Func start:           " + fieldAddr.toString("0x") + " => " + ptrAddr.toString("0x"));
				Function existingFunc = getFunctionAt(ptrAddr);
				if (existingFunc == null) {
					// function doesn't exist so check if is code
					Instruction existingInstr = getInstructionAt(ptrAddr);
					if (existingInstr == null) {
						// no code at address
						dualPrintln(funcName + " Disassembling at:     " + ptrAddr.toString("0x"));
						clearListing(ptrAddr);
						disassemble(ptrAddr);
					}
					existingFunc = getFunctionAt(ptrAddr);
					if( existingFunc == null ) {
						dualPrintln(funcName + " Creating Func at:     " + ptrAddr.toString("0x"));

						Function newFunc = createFunction(ptrAddr, ptrPrefixSuffix); // TODO
						if (newFunc == null) {
							newFunc = listing.getFunctionAt(ptrAddr);
							if (newFunc == null) {
								dualPrintln(funcName + " Error: null pointer for function at " + ptrAddr.toString("0x"));
								throw new Exception();
							} else {
								dualPrintln(funcName + " Func:                 " + ptrAddr.toString("0x") + " with name: " + newFunc.getName());
							}
						} else {
							Namespace ns = symbolTable.getNamespace(className, currentProgram.getGlobalNamespace());
							newFunc.setParentNamespace(ns);
							dualPrintln(funcName + " Func:                 " + ptrAddr.toString("0x") + " with name: " + newFunc.getName());
						}
					}
				} else {
					// fuction exist so check name
					String existingName = existingFunc.getName(true);
					boolean alreadyRenamed = existingName.contains("::");
					if (alreadyRenamed) {
						dualPrintln(funcName + " Func already renamed: " + ptrAddr.toString("0x") + " not done existing name [" + existingName + "] would have done " + existingFunc.getName() + " => " + funcName);
					} else {
						if (!existingFunc.getName(true).equals(funcName)) {
							dualPrint(funcName + " Func renaming:        " + ptrAddr.toString("0x") + " with name: " + existingFunc.getName(true));
							existingFunc.setName(funcName, SourceType.USER_DEFINED);
							dualPrintln( " => " + existingFunc.getName(true));
						}
					}
				}
				dualPrintln(funcName + " Func end:             " + fieldAddr.toString("0x") + " => " + ptrAddr.toString("0x"));
			}
		}
	}

	class SShortString {
		int    len;
		String value;

		SShortString(Address addr) throws Exception {
			//dualPrintln("-------------------SShortString ["+addr.toString("0x")+"]-------------------");
			Address offsetAddr  = addr.add(0x00);
			Address offsetAddr1 = addr.add(0x01);
			clearListing( offsetAddr );
			Data dLen = createByte( offsetAddr );
			len = (int)((Scalar) dLen.getValue()).getValue();
			for( int i=0; i<len; i++ ) {
				clearListing( offsetAddr1.add(i) );
			}
			Data nameData = createAsciiString( addr.add(0x01), len );
			value = (String) nameData.getValue();
			Symbol strSymbol = createLabel(addr, value, true);
			//dualPrintln("-------------------SShortString ["+addr.toString("0x")+"] ("+ value +")-------------------");
		}
	}

}
