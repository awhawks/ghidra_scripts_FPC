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
// Search for VMT table entries and assign structure
//@category AWH
//@menupath AWH.Search_VMT_Struct
//@toolbar search_struct.png

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.GenericAddress;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.StructureFactory;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.util.Date;
import java.util.Iterator;

public class AWH_Search_VMT_Struct extends GhidraScript {
	private AddressFactory  addressFactory;
	private DataTypeManager bultInDataTypeManager;
	private DataTypeManager dataTypeManager;
	private FunctionManager functionManager;
	private Listing         listing;
	private Memory          memory;
	private SymbolTable     symbolTable;

	private DataType    BYTE;
	private DataType    WORD;
	private DataType    INT;
	private DataType    LONG;
	private DataType    PTR64;
	private DataType    STRING;
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
		addressFactory        = currentProgram.getAddressFactory();
		bultInDataTypeManager = BuiltInDataTypeManager.getDataTypeManager();
		dataTypeManager       = currentProgram.getDataTypeManager();
		functionManager       = currentProgram.getFunctionManager();
		listing               = currentProgram.getListing();
		memory                = currentProgram.getMemory();
		symbolTable           = currentProgram.getSymbolTable();

		MemoryBlock dataBlock = memory.getBlock(".data");
		dataStart = dataBlock.getStart();
		dataEnd   = dataBlock.getEnd();

		MemoryBlock textBlock = memory.getBlock(".text");
		textStart = textBlock.getStart();
		textEnd   = textBlock.getEnd();

		Iterator<DataType> dti = bultInDataTypeManager.getAllDataTypes();
		while (dti.hasNext()) {
			if (monitor.isCancelled()) {
				break;
			}
			DataType dt = dti.next();
			String path = dt.getDataTypePath().getPath();
			dualPrintln("DataType path: " + path);
			switch (path) {
				case "/byte":
					BYTE = dt;
					break;
				case "/word":
					WORD = dt;
					break;
				case "/int":
					INT = dt;
					break;
				case "/longlong":
					LONG = dt;
					break;
				case "/pointer64":
					PTR64 = dt;
					break;
				case "/TerminatedCString":
					CSTRING = dt;
					break;
				case "/string":
					STRING = dt;
					break;
			}
		}
		if (BYTE == null) {
			dualPrintln("DataType [/byte             ] not found.");
			throw new Exception();
		}
		if (WORD == null) {
			dualPrintln("DataType [/word             ] not found.");
			throw new Exception();
		}
		if (INT == null) {
			dualPrintln("DataType [/int              ] not found.");
			throw new Exception();
		}
		if (LONG == null) {
			dualPrintln("DataType [/longlong         ] not found.");
			throw new Exception();
		}
		if (PTR64 == null) {
			dualPrintln("DataType [/pointer64        ] not found.");
			throw new Exception();
		}
		if (STRING == null) {
			dualPrintln("DataType [/string           ] not found.");
			throw new Exception();
		}
		if (CSTRING == null) {
			dualPrintln("DataType [/TerminatedCString] not found.");
			throw new Exception();
		}
		dualPrintln("Date: " + new Date(System.currentTimeMillis()) );
		dualPrintln("programFile:  " + getProgramFile().getAbsolutePath());
		dualPrintln("current addr: " + currentAddress.toString("0x"));
		dualPrintln(String.format("name: %-20s 0x%-15s 0x%-15s", dataBlock.getName(), dataStart, dataEnd));
	}

	@Override
	protected void run() throws Exception {
		File outputFile = new File( getProgramFile().getParentFile(), "AWH_VMT_search_Struct.txt");
		pWriter = new PrintWriter(new FileOutputStream(outputFile));
		println("pWriter: "+pWriter);
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
						dualPrintln("VMT seems valid at: " + vmtAddr.toString("0x") );
						Symbol[] symbols = symbolTable.getSymbols(vmtAddr);
						String syms = "";
						for (Symbol symbol : symbols) {
							syms += " [" + symbol.getName(true) + "]";
						}
						Data     vmtData     = listing.getDataAt(vmtAddr);
						boolean createVMTStruct = false;
						if( vmtData == null ){
							createVMTStruct = true;
						} else {
							DataType vmtDataType = vmtData.getDataType();
							if (vmtData.isStructure() && vmtDataType.getPathName().equals("/AWH_VMT")) {
								dualPrintln("VMT already exists at " + vmtAddr.toString("0x"));
							} else {
								createVMTStruct = true;
							}
						}
						if( createVMTStruct ){
							dualPrintln("VMT Struct being created at: " + vmtAddr.toString("0x") );
							for( int i=0; i<0xC8;i++) {
								clearListing( vmtAddr.add(i) );
							}
							Address classnameDstAddr = getPtrDstAddress( vmtAddr.add(0x18) );
							SShortString ss = new SShortString(classnameDstAddr);
							createVMTStructure(vmtAddr, ss);
							//symbolTable.createLabel( vmtAddr, "GL_VMT_" + ss.value, SourceType.USER_DEFINED );
						}
						dualPrintln(String.format("[%s - %s][%s]found: %s VMT: %s  %s",
								dataStart.toString("0x"),
								dataEnd.toString("0x"),
								start.toString("0x"),
								foundBytes.toString("0x"),
								vmtAddr.toString("0x"),
								syms
						));
						//new SVMT(vmtAddr);
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
			analyzeChanges( currentProgram );
		} catch (Exception e){
			if( e.getMessage() != null ){
				pWriter.write( e.getMessage() );
			}
			e.printStackTrace(pWriter);
			throw e;
		} finally {
			pWriter.close();
		}
	}

	private void createVMTStructure(Address vmtAddr, SShortString ss) throws Exception {
		Structure vmtDataStruct = StructureFactory.createStructureDataType(currentProgram, vmtAddr, 0xC8, "VMT_"+ss.value, true);
		vmtDataStruct.replaceAtOffset( 0x00, LONG,  -1, "instanceSize",           "VMT instance size" );
		vmtDataStruct.replaceAtOffset( 0x08, LONG,  -1, "instanceSize2c",         "VMT instance size two's complement" );
		vmtDataStruct.replaceAtOffset( 0x10, PTR64, -1, "parent",                 "VMT Parent VMT instance pointer" );
		vmtDataStruct.replaceAtOffset( 0x18, PTR64, -1, "classname",              "VMT classname pointer" );
		vmtDataStruct.replaceAtOffset( 0x20, PTR64, -1, "dynamicTable",           "VMT dynamicTable pointer" );
		vmtDataStruct.replaceAtOffset( 0x28, PTR64, -1, "methodTable",            "VMT methodTable pointer" );
		vmtDataStruct.replaceAtOffset( 0x30, PTR64, -1, "fieldTable",             "VMT fieldTable pointer" );
		vmtDataStruct.replaceAtOffset( 0x38, PTR64, -1, "typeInfo",               "VMT typeInfo pointer" );
		vmtDataStruct.replaceAtOffset( 0x40, PTR64, -1, "initTable",              "VMT initTable pointer" );
		vmtDataStruct.replaceAtOffset( 0x48, PTR64, -1, "autoTable",              "VMT autoTable pointer" );
		vmtDataStruct.replaceAtOffset( 0x50, PTR64, -1, "intfTable",              "VMT intfTable pointer" );
		vmtDataStruct.replaceAtOffset( 0x58, PTR64, -1, "msgStrPtr",              "VMT msgStrPtr pointer" );
		vmtDataStruct.replaceAtOffset( 0x60, PTR64, -1, "func_destroy",           "VMT func_destroy pointer" );
		vmtDataStruct.replaceAtOffset( 0x68, PTR64, -1, "func_newInstance",       "VMT func_newInstance pointer" );
		vmtDataStruct.replaceAtOffset( 0x70, PTR64, -1, "func_freeInstance",      "VMT func_freeInstance pointer" );
		vmtDataStruct.replaceAtOffset( 0x78, PTR64, -1, "func_safeCallException", "VMT func_safeCallException pointer" );
		vmtDataStruct.replaceAtOffset( 0x80, PTR64, -1, "func_defaultHandler",    "VMT func_defaultHandler pointer" );
		vmtDataStruct.replaceAtOffset( 0x88, PTR64, -1, "func_afterConstruction", "VMT func_afterConstruction pointer" );
		vmtDataStruct.replaceAtOffset( 0x90, PTR64, -1, "func_beforeDestruction", "VMT func_beforeDestruction pointer" );
		vmtDataStruct.replaceAtOffset( 0x98, PTR64, -1, "func_defaultHandlerStr", "VMT func_defaultHandlerStr pointer" );
		vmtDataStruct.replaceAtOffset( 0xA0, PTR64, -1, "func_dispatch",          "VMT func_dispatch pointer" );
		vmtDataStruct.replaceAtOffset( 0xA8, PTR64, -1, "func_dispatchStr",       "VMT func_dispatchStr pointer" );
		vmtDataStruct.replaceAtOffset( 0xB0, PTR64, -1, "func_equals",            "VMT func_equals pointer" );
		vmtDataStruct.replaceAtOffset( 0xB8, PTR64, -1, "func_getHashCode",       "VMT func_getHashCode pointer" );
		vmtDataStruct.replaceAtOffset( 0xC0, PTR64, -1, "func_toString",          "VMT func_toString pointer" );
		int funcNum = 0;
		Long ptrValue = getLongValue( vmtAddr.add(0xC8 + funcNum * 8));
		while( ptrValue != 0){
			vmtDataStruct.add( PTR64,                8, "func" + (++funcNum), "VMT Class function pointer" );
			clearListing( vmtAddr.add(0xC8 + funcNum * 8) );
			ptrValue = getLongValue( vmtAddr.add(0xC8 + funcNum * 8));
		}
		int dataSize = vmtDataStruct.getLength();
		for( int i=0; i<dataSize; i++){
			clearListing( vmtAddr.add(i) );
		}
		Data vmtData = createData( vmtAddr, vmtDataStruct );
		createLabel( vmtAddr, "AWH_" + vmtDataStruct.getName(), true, SourceType.USER_DEFINED );
		int offset = 0x20;
		if( ((GenericAddress)vmtData.getComponentAt(offset).getValue()).getUnsignedOffset() != 0 ) {
			createDynamicTableStructure( getPtrDstAddress( vmtAddr.add(offset) ), ss);
		}
		offset = 0x28;
		if( ((GenericAddress)vmtData.getComponentAt(offset).getValue()).getUnsignedOffset() != 0 ) {
			createMethodTableStructure( getPtrDstAddress( vmtAddr.add(offset) ), ss);
		}
		offset = 0x30;
		if( ((GenericAddress)vmtData.getComponentAt(offset).getValue()).getUnsignedOffset() != 0 ) {
			createFieldTableStructure( getPtrDstAddress( vmtAddr.add(offset) ), ss);
		}
		offset = 0x38;
		if( ((GenericAddress)vmtData.getComponentAt(offset).getValue()).getUnsignedOffset() != 0 ) {
			createTypeInfoStructure(getPtrDstAddress(vmtAddr.add(offset)), ss);
		}
		offset = 0x40;
		if( ((GenericAddress)vmtData.getComponentAt(offset).getValue()).getUnsignedOffset() != 0 ) {
			createInitTableStructure( getPtrDstAddress( vmtAddr.add(offset) ), ss);
		}
		offset = 0x48;
		if( ((GenericAddress)vmtData.getComponentAt(offset).getValue()).getUnsignedOffset() != 0 ) {
			createAutoTableStructure( getPtrDstAddress( vmtAddr.add(offset) ), ss);
		}
		offset = 0x50;
		if( ((GenericAddress)vmtData.getComponentAt(offset).getValue()).getUnsignedOffset() != 0 ) {
			createIntfTableStructure( getPtrDstAddress( vmtAddr.add(offset) ), ss);
		}
		offset = 0x58;
		if( ((GenericAddress)vmtData.getComponentAt(offset).getValue()).getUnsignedOffset() != 0 ) {
			createmsgStrStructure( getPtrDstAddress( vmtAddr.add(offset) ), ss);
		}
	}

	private void createDynamicTableStructure(Address addr, SShortString ss) {
		dualPrintln("Would be creating structure here for dynamic table");
	}

	private void createMethodTableStructure(Address addr, SShortString ss) {
		dualPrintln("Would be creating structure here for method table");
	}

	private void createFieldTableStructure(Address addr, SShortString ss) {
		dualPrintln("Would be creating structure here for field table");
	}

	private void createTypeInfoStructure(Address addr, SShortString ss) throws Exception {
		clearListing(addr.add(0x01));
		int classnameLen = ((int) memory.getByte( addr.add( 0x01 ) )) & 0xFF;
		clearListing(addr.add(0x01));
		Structure vmtTypeInfoDataStruct = StructureFactory.createStructureDataType(currentProgram, addr, 0x02, "TypeInfo_"+ss.value, true);
		vmtTypeInfoDataStruct.replaceAtOffset( 0x00, BYTE,      -1, "classTypeEnum", "VMT typeInfo Enum int" );
		vmtTypeInfoDataStruct.replaceAtOffset( 0x01, BYTE,      -1, "classnameLen",  "VMT typeInfo Classname length" );
		vmtTypeInfoDataStruct.add( STRING, classnameLen, "classname",      "VMT TypeInfo Classname");
		vmtTypeInfoDataStruct.add( PTR64,     -1, "typeInfoVMTPtr", "VMT TypeInfo pointer to VMT" );
		vmtTypeInfoDataStruct.add( PTR64,     -1, "typeInfoParent", "VMT TypeInfo pointer to parent TypeInfo" );
		int dataSize = vmtTypeInfoDataStruct.getLength();
		for( int i=0; i<dataSize; i++){
			clearListing( addr.add(i) );
		}
		Data vmtTypeInfoData = createData( addr, vmtTypeInfoDataStruct );
		createLabel( addr, "AWH_" + vmtTypeInfoDataStruct.getName(), true, SourceType.USER_DEFINED );
		//dualPrintln( "TypeInfo vmtPtr: " + vmtTypeInfoData.getComponent(3).getValue() );
		//dualPrintln( "TypeInfo parent: " + vmtTypeInfoData.getComponent(4).getValue() );
	}

	private void createInitTableStructure(Address addr, SShortString ss) {
		dualPrintln("Would be creating structure here for init table");
	}

	private void createAutoTableStructure(Address addr, SShortString ss) {
		dualPrintln("Would be creating structure here for auto table");
	}

	private void createIntfTableStructure(Address addr, SShortString ss) {
		dualPrintln("Would be creating structure here for intf table");
	}

	private void createmsgStrStructure(Address addr, SShortString ss) {
		dualPrintln("Would be creating structure here for msgStr");
	}

	private Long getLongValue( Address addr ) throws MemoryAccessException {
		Long result = memory.getLong( addr );
		//dualPrintln("longValue of: " + addr.toString("0x") + " = " + String.format("0x%X", result) );
		return result;
	}

	private Address getPtrDstAddress( Address addr ) throws MemoryAccessException {
		Long ptrValue = getLongValue( addr );
		Address result = parseAddress( toHexString( ptrValue, true, true) );
		//dualPrintln("dstAddr of: " + addr.toString("0x") + " = " + result.toString("0x") );
		return result;
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
		long[] longArray = new long[25];
		int numRetrieved = memory.getLongs(vmtAddr, longArray);
		long valOfInstanceSize      = longArray[ 0]; // 0x00
		long valOfInstanceSize2     = longArray[ 1]; // 0x08
		long valOfParent            = longArray[ 2]; // 0x10
		long valOfClassName         = longArray[ 3]; // 0x18
		long valOfTypeInfo          = longArray[ 7]; //0x38
		long valOfDestroy           = longArray[12]; //0x60
		long valOfNewInstance       = longArray[13]; //0x68
		long valOfFreeInstance      = longArray[14]; //0x70
		long valOfSafeCallException = longArray[15]; //0x78
		long valOfDefaultHandler    = longArray[16]; //0x80
		long valOfAfterConstruction = longArray[17]; //0x88
		long valOfBeforeDestruction = longArray[18]; //0x90
		long valOfDefaultHandlerStr = longArray[19]; //0x98
		long valOfDispatch          = longArray[20]; //0xA0
		long valOfDispatchStr       = longArray[21]; //0xA8
		long valOfEquals            = longArray[22]; //0xB0
		long valOfGetHashCode       = longArray[23]; //0xB8
		long valOfToString          = longArray[24]; //0xC0

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

	class SShortString {
		int    len;
		String value;

		SShortString(Address addr) throws Exception {
			dualPrintln("-------------------SShortString ["+addr.toString("0x")+"]-------------------");
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
			Symbol strSymbol = createLabel(addr, "SS_"+value, true);
			dualPrintln("-------------------SShortString ["+addr.toString("0x")+"] ("+ value +")-------------------");
		}
	}

}
