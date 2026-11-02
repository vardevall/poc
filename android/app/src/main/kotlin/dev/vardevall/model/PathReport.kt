package dev.vardevall.model

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** A network of the device that is not the tunnel, as `ConnectivityManager` describes it. */
data class UnderlyingNetwork(
    val id: Long,
    val interfaceName: String?,
    /** The index of the interface, which a link-local resolver needs. */
    val interfaceIndex: Int,
    val addresses: List<String>,
    val resolvers: List<String>,
    val metered: Boolean,
)

/** What the engine is told about the paths of the device (`vv_path_changed`). */
object PathReport {
    /** The families, "v4" and "v6", of an address as `InetAddress.hostAddress` prints it. */
    fun family(address: String) = if (':' in address) "v6" else "v4"

    /** The addresses of the networks, by family. */
    fun addresses(networks: List<UnderlyingNetwork>): Map<String, Set<String>> =
        networks.flatMap { n -> n.addresses.map { family(it) to "${n.id}/$it" } }
            .groupBy({ it.first }, { it.second })
            .mapValues { it.value.toSet() }

    /** The families whose addresses differ; null when none does or nothing was known before. */
    fun changedFamilies(before: Map<String, Set<String>>?, after: Map<String, Set<String>>): List<String>? {
        if (before == null) return null
        val changed = listOf("v4", "v6").filter { before[it].orEmpty() != after[it].orEmpty() }
        return changed.ifEmpty { null }
    }

    /**
     * The argument of `vv_path_changed`: whether the interface in use is [metered], which
     * interfaces are, and the [families] that changed.
     */
    fun json(changed: Boolean, metered: Boolean, networks: List<UnderlyingNetwork>, families: List<String>?): String {
        val members = mutableMapOf<String, kotlinx.serialization.json.JsonElement>(
            "changed" to JsonPrimitive(changed),
            "metered" to JsonPrimitive(metered),
            "interfaces" to JsonArray(
                networks.mapNotNull { n ->
                    n.interfaceName?.let { JsonObject(mapOf("name" to JsonPrimitive(it), "metered" to JsonPrimitive(n.metered))) }
                },
            ),
        )
        if (families != null) members["families"] = JsonArray(families.map { JsonPrimitive(it) })
        return JsonObject(members).toString()
    }

    /** The resolvers to hand to the engine: the active network's first, then the others', without repeats. */
    fun resolvers(networks: List<UnderlyingNetwork>, active: Long?): List<String> =
        (networks.filter { it.id == active } + networks.filter { it.id != active })
            .flatMap { it.resolvers }
            .distinct()

    /** A resolver address as the engine takes it: a link-local one carries its interface index. */
    fun resolver(address: String, interfaceIndex: Int): String =
        if (address.lowercase().startsWith("fe80:") && '%' !in address && interfaceIndex > 0) "$address%$interfaceIndex" else address
}
