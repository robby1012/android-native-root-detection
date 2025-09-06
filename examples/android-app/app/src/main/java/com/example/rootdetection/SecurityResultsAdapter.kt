package com.example.rootdetection

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.RecyclerView
import com.example.rootdetection.databinding.ItemSecurityResultBinding
import java.text.SimpleDateFormat
import java.util.*

/**
 * RecyclerView adapter for displaying security scan results.
 */
class SecurityResultsAdapter(
    private val results: MutableList<SecurityResultItem>
) : RecyclerView.Adapter<SecurityResultsAdapter.SecurityResultViewHolder>() {

    private val timeFormat = SimpleDateFormat("HH:mm:ss", Locale.getDefault())

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): SecurityResultViewHolder {
        val binding = ItemSecurityResultBinding.inflate(
            LayoutInflater.from(parent.context), parent, false
        )
        return SecurityResultViewHolder(binding)
    }

    override fun onBindViewHolder(holder: SecurityResultViewHolder, position: Int) {
        holder.bind(results[position])
    }

    override fun getItemCount(): Int = results.size

    inner class SecurityResultViewHolder(
        private val binding: ItemSecurityResultBinding
    ) : RecyclerView.ViewHolder(binding.root) {

        fun bind(item: SecurityResultItem) {
            binding.apply {
                textIcon.text = item.icon
                textMessage.text = item.message
                textTimestamp.text = timeFormat.format(Date(item.timestamp))
                
                // Set colors based on status
                val context = binding.root.context
                val textColor = when (item.status) {
                    SecurityStatus.SUCCESS -> ContextCompat.getColor(context, R.color.status_success)
                    SecurityStatus.WARNING -> ContextCompat.getColor(context, R.color.status_warning)
                    SecurityStatus.ERROR -> ContextCompat.getColor(context, R.color.status_error)
                    SecurityStatus.INFO -> ContextCompat.getColor(context, R.color.status_info)
                }
                
                textMessage.setTextColor(textColor)
                textIcon.setTextColor(textColor)
            }
        }
    }
}

/**
 * Data class representing a security scan result item.
 */
data class SecurityResultItem(
    val icon: String,
    val message: String,
    val status: SecurityStatus,
    val timestamp: Long
)

/**
 * Enum representing the status/severity of a security result.
 */
enum class SecurityStatus {
    SUCCESS,    // Green - No issues
    WARNING,    // Orange - Potential issues
    ERROR,      // Red - Serious issues
    INFO        // Blue - Informational
}
