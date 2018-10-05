package org.marcusbb.crypto.policy;

import java.lang.reflect.Field;

public interface PolicyEvaluator {

	/**
	 * 
	 * @param policy
	 * @param field - the java field that is described
	 * 
	 * @return
	 */
	public Result evaluate(Policy policy, Field field);
	
	
	/**
	 * 
	 * The result of a Policy Evaluator operation
	 *
	 */
	public static enum Result {
		OK,
		DENIED,
		INSUFFICIENT,		
	}
}
