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
 *
 * Adapted from ExportFunctionInfoScript.java, inspired by
 * Christopher Robert's Firmware Slap
 */
// List function names and verbose metadata to a file in JSON format
//@category Functions

// Headless invocation:
/*
~/Downloads/ghidra_10.1.4_PUBLIC/support/analyzeHeadless /PATH/TO/GHIDR/PROJECT GHIDRA_PROJECT 
-process layers.bin
-postScript  ExportFunctionInfoScriptVerbose.java 
-scriptPath /PATH/TO/THIS/SCRIPT 
-readOnly 
*/

import java.io.File;
import java.io.FileWriter;

import com.google.gson.*;
import com.google.gson.stream.JsonWriter;

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.ClangTokenGroup;

import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockImpl;
import ghidra.program.model.block.SimpleBlockModel;
import ghidra.program.model.block.SimpleBlockIterator;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeDataTypeManager;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.FunctionPrototype;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.pcode.HighSymbol;

import ghidra.util.task.TaskMonitor;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.CancelledException;

public class ExportFunctionInfoScriptVerbose extends GhidraScript {

	private static final String NAME = "name";
	private static final String ENTRY = "entry";
	private static CodeBlock cb = null;

	//==========================================================================
	private void autoCommitParameters(DecompInterface ifc, Program p, Function f, int timeout){
		/*
		Students are not expected to do this, but included as bonus content.
		Adapted from the Ghidra API Docs
		*/
	
		// Make calls to the decompiler:
		DecompileResults res = ifc.decompileFunction(f,0, null);
		
		// Check for error conditions
		if (!res.decompileCompleted()) {
			println(res.getErrorMessage());
			return;
		}
		
		// Make use of results
		// Get C code
		ClangTokenGroup tokgroup = res.getCCodeMarkup();
		// Get the function object/syntax tree
		HighFunction hfunc = res.getHighFunction();
		FunctionPrototype functionPrototype = hfunc.getFunctionPrototype();	

		printf("%s() signature: %s\n", f.getName(), functionPrototype.getReturnType().toString());
		for (int i = 0; i < functionPrototype.getNumParams(); i++) {
			HighSymbol parameter = functionPrototype.getParam(i);
			printf("%s\n",parameter.getDataType().toString() + " " + parameter.getName());
		}


		try{
			HighFunctionDBUtil.commitReturnToDatabase(hfunc, SourceType.ANALYSIS);
			HighFunctionDBUtil.commitParamsToDatabase(hfunc, true, SourceType.ANALYSIS);		
		}
		catch(DuplicateNameException | InvalidInputException e){
			println(e.toString());
		}
	}
	//==========================================================================
	private int getNumBlocksInFunction(Function f, SimpleBlockModel sbm, TaskMonitor monitor){
		// Returns # of code blocks in a function or -1 on error
		// It's worth noting the initialization and use of the 
		// Block iterators significantly increase the runtime		
		int numBlocks = 0;

		try{
			SimpleBlockIterator sbi = new SimpleBlockIterator(sbm, f.getBody(), monitor);
		
			while(sbi.hasNext()){
				sbi.next();
				numBlocks++;
			}
		}
		catch(CancelledException ignore){
			numBlocks = -1;
		}
		return numBlocks;
	}
	//==========================================================================
	int getNumBlocksInFunctionv2(Function f, SimpleBlockIterator sbi){
		int numberOfCodeBlocks = 0;
		//printf("-------------------------------------\n");
		//printf("%s %s\n", f.getName(), f.getEntryPoint().toString() );
		try{
			while(sbi.hasNext()){
				//printf("cb: %s-%s\n", cb.getMinAddress().toString(), cb.getMaxAddress().toString());

				if (cb == null){
					cb = sbi.next();
				}
				if (f.getBody().contains(cb.getMinAddress(), cb.getMaxAddress())){
					numberOfCodeBlocks++;
					cb = sbi.next();
				}
				else if (f.getBody().getMinAddress().compareTo(cb.getMaxAddress()) > 0){
					cb = sbi.next();
				}
				else{
					break;
				} 
				//printf("cb: %s-%s\n", cb.getMinAddress().toString(), cb.getMaxAddress().toString());
			}

			if(!sbi.hasNext() && cb != null){
				if (f.getBody().contains(cb.getMinAddress(), cb.getMaxAddress())){
					numberOfCodeBlocks++;		
					cb = null;
				}		
			}
		}
		catch(CancelledException ignore){
			numberOfCodeBlocks = -1;
		}
		return numberOfCodeBlocks;
	}
			
	//==========================================================================
	private JsonArray getAllVariables(Function f){
		/* IMPORTANT NOTE
		This function will return 0 parameters for non-libraries functions
		unless the function's signature has been "commited".
		To do this in the GUI, navigate to the function, open decompiler view,
		right-click, and select "Commit Params/Return" or use hotkey "P"
		This script will also do this automatically via the function above if
		the user enters "y" at the first prompt.  
		This is also the scripts default behavior.
		*/
		
		JsonArray ja = new JsonArray();
		for (Variable v: f.getAllVariables())
		{
			JsonObject json2 = new JsonObject();
			try{
				json2.addProperty("name", v.getName());
				json2.addProperty("dataType", v.getDataType().toString());
				json2.addProperty("isCompoundVariable", v.isCompoundVariable());
				json2.addProperty("length", v.getLength());
				json2.addProperty("symbol", v.getSymbol().toString());

			}
			catch(NullPointerException e){
				println(e.toString());
			}
			ja.add(json2);
		}
		return ja;
	}
	//==========================================================================
	private JsonArray getParameters(Function f){
		
		JsonArray ja = new JsonArray();
		for (Parameter p: f.getParameters())
		{
			JsonObject json2 = new JsonObject();
			try{
				json2.addProperty("name", p.getName());
				json2.addProperty("ordinal", p.getOrdinal());
				json2.addProperty("dataType", p.getDataType().toString());
				json2.addProperty("isCompoundParameter", p.isCompoundVariable());
				json2.addProperty("length", p.getLength());
				json2.addProperty("symbol", p.getSymbol().toString());

			}
			catch(NullPointerException e){
				println(e.toString());
			}
			ja.add(json2);
		}
		return ja;
	}	
	//==========================================================================
	@Override
	public void run() throws Exception {

		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		DecompInterface ifc = null;

		//File outputFile = askFile("Please Select Output File", "Choose");
		//JsonWriter jsonWriter = new JsonWriter(new FileWriter(outputFile));

		Boolean autoCommitBool = true;
		int timeout = 30;
		String autoCommitString = askString("Commit function parameters",
									"Would you like to commit function parameter value and return? This is recommended, otherwise the results of this script may not match the decompiled view in the GUI. [y/Y/]",
									"y");
		if(autoCommitString.equals("y") || autoCommitString.equals("Y")){
			printf("Will commit commit function parameter and returns.\n");
			ifc = new DecompInterface();			
			// Setup any options or other initialization
			//ifc.setOptions(xmlOptions); // Inform interface of global options
			// ifc.toggleSyntaxTree(false);  // Don't produce syntax trees
			// ifc.toggleCCode(false);       // Don't produce C code
			// ifc.setSimplificationStyle("normalize"); // Alternate analysis style
			
			// Setup up the actual decompiler process for a
			// particular program, using all the above initialization
			ifc.openProgram(currentProgram);			
		}


		String defaultFileName = "/tmp/" + currentProgram.getName() + "_functionMetadata.json";
		String outputFile = askString("Output", "Please provide name of file for output:", defaultFileName);
		JsonWriter jsonWriter = new JsonWriter(new FileWriter(outputFile));
		
		jsonWriter.beginArray();

		Listing listing = currentProgram.getListing();
		FunctionIterator iter = listing.getFunctions(true);
		SimpleBlockModel sbm = new SimpleBlockModel(currentProgram);

		SimpleBlockIterator sbi = new SimpleBlockIterator(sbm, monitor);
		cb = sbi.next();
		int numberOfCodeBlocks = 0;
		int numberOfCodeBlocksv2 = 0;

		while (iter.hasNext() && !monitor.isCancelled()) {
			printf("-------------------------------------\n");

			numberOfCodeBlocks = 0;
			Function f = iter.next();

			if (autoCommitBool){;
				//printf("Commit params for %s\n", f.getName());
				autoCommitParameters(ifc, currentProgram, f, timeout);
			}

			String name = f.getName();
			Address entry = f.getEntryPoint();

			// These were already in ExportFunctionInfoScript
			JsonObject json = new JsonObject();
			json.addProperty(NAME, name);
			json.addProperty(ENTRY, entry.toString());

			// I added everything else
			// Get metadata that is a primitive type or can be cast to string
			json.addProperty("parameterCount", f.getParameterCount());
			json.addProperty("parameters", f.getParameters().toString());
			json.addProperty("callingConvention", f.getCallingConventionName());
			json.addProperty("callingFunctions", f.getCallingFunctions(null).toString());
			json.addProperty("calledFunctions", f.getCalledFunctions(null).toString());
			json.addProperty("signature", f.getSignature().toString());

			// The line below is bonus material for classroom instruction
			// It's worth noting the initialization and use of the 
			// Block iterators significantly increase the runtime
			numberOfCodeBlocks = getNumBlocksInFunction(f, sbm, monitor);
			//numberOfCodeBlocksv2 = getNumBlocksInFunctionv2(f, sbi);
			json.addProperty("numberOfCodeBlocks", numberOfCodeBlocks);
			//json.addProperty("numberOfCodeBlocksv2", numberOfCodeBlocksv2);
			if (numberOfCodeBlocks != numberOfCodeBlocksv2){
				printf("%s\n", f.getName());
				printf("%s %d != %d\n", f.getName(), numberOfCodeBlocks, numberOfCodeBlocksv2);
				printf(f.getName());
			} 

			// Get metadata that is returned as an array
			// I wrote helper functions for these
			json.add("parameters", getParameters(f));
			json.add("variables", getAllVariables(f));

			gson.toJson(json, jsonWriter);
		}

		jsonWriter.endArray();
		jsonWriter.close();

		printf("Wrote function metadata to %s\n", outputFile);	
	}
}
