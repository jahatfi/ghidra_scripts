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
 * Adapted from ExportFunctionInfoScript.java
 */
// List function names and verbose metadata to a file in JSON format
//@category Functions

import java.io.File;
import java.io.FileWriter;

import com.google.gson.*;
import com.google.gson.stream.JsonWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

public class ExportFunctionInfoScriptVerbose extends GhidraScript {

	private static final String NAME = "name";
	private static final String ENTRY = "entry";

	private JsonArray getAllVariables(Function f){
		/* IMPORTANT NOTE
		This function will return 0 parameters for non-libraries functions
		unless the function's signature has been "commited."
		To do this in the GUI, navigate to the function, open decompiler view,
		right-click, and select "Commit Params/Return" or use hotkey "P"
		For help on doing this programmatically, see the Ghidra API docs on 
		the HighFunctionDBUtil class
		*/
		Variable[] theseVariables = f.getAllVariables();
		
		JsonArray ja = new JsonArray();
		for (int i = 0; i < theseVariables.length; i++)
		{
			JsonObject json2 = new JsonObject();
			try{
				json2.addProperty("name", theseVariables[i].getName());
				json2.addProperty("dataType", theseVariables[i].getDataType().toString());
				json2.addProperty("isCompoundVariable", theseVariables[i].isCompoundVariable());
				json2.addProperty("length", theseVariables[i].getLength());
				json2.addProperty("symbol", theseVariables[i].getSymbol().toString());

			}
			catch(NullPointerException e){
				println(e.toString());
			}
			ja.add(json2);
		}
		return ja;
	}


	private JsonArray getParameters(Function f){
		Parameter[] theseParameters = f.getParameters();
		
		JsonArray ja = new JsonArray();
		for (int i = 0; i < theseParameters.length; i++)
		{
			JsonObject json2 = new JsonObject();
			try{
				json2.addProperty("name", theseParameters[i].getName());
				json2.addProperty("ordinal", theseParameters[i].getOrdinal());
				json2.addProperty("dataType", theseParameters[i].getDataType().toString());
				json2.addProperty("isCompoundParameter", theseParameters[i].isCompoundVariable());
				json2.addProperty("length", theseParameters[i].getLength());
				json2.addProperty("symbol", theseParameters[i].getSymbol().toString());

			}
			catch(NullPointerException e){
				println(e.toString());
			}
			ja.add(json2);
		}
		return ja;
	}	

	@Override
	public void run() throws Exception {

		Gson gson = new GsonBuilder().setPrettyPrinting().create();

		//File outputFile = askFile("Please Select Output File", "Choose");
		//JsonWriter jsonWriter = new JsonWriter(new FileWriter(outputFile));
		String defaultFileName = "/tmp/" + currentProgram.getName() + "_functionMetadata.json";
		String outputFile = askString("Output", "Please provide name of file for output:", defaultFileName);
		JsonWriter jsonWriter = new JsonWriter(new FileWriter(outputFile));
		
		jsonWriter.beginArray();

		Listing listing = currentProgram.getListing();
		FunctionIterator iter = listing.getFunctions(true);
		while (iter.hasNext() && !monitor.isCancelled()) {
			Function f = iter.next();

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
			json.addProperty("string", f.toString());

			// Get metadata that is returned as an array
			// I wrote helper functions for these
			json.add("parameters", getParameters(f));
			json.add("variables", getAllVariables(f));

			gson.toJson(json, jsonWriter);
		}

		jsonWriter.endArray();
		jsonWriter.close();

		println("Wrote function metadata to " + outputFile);	
	}
}
