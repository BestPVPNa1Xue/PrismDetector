package icu.nullptr.applistdetector

import android.content.Context

/**
 *Created by byxiaorun on 2024/1/9.
 */
class Account(context: Context, var accountlist: List<String>, override val name: String) : IDetector(context) {

    override fun run(packages: Collection<String>?, detail: Detail?): Result {
        var result = Result.NOT_FOUND
        val add: (Pair<String, Result>) -> Unit = {
            result = result.coerceAtLeast(it.second)
            detail?.add(it)
        }
        if (accountlist.isNotEmpty()) {
            accountlist.forEach { add(Pair(it, Result.SUSPICIOUS)) }
        } else {
            add(Pair("Accountlist", Result.NOT_FOUND))
        }
        return result
    }

}