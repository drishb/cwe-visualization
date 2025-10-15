<template>
  <div class="flex h-screen">
    
    <!-- Left Sidebar - CWE Information -->
    <div class="w-1/3 min-w-[250px] max-w-[800px] bg-gray-100 p-4 overflow-y-auto space-y-4">
      <h2 class="text-3xl font-bold">Common Weakness Enumeration Tree Navigation</h2>

      <h3 class="text-xl font-semibold">CWE View: Research Concepts</h3>

      <h3>Choose a graph visualization:</h3>

      <select v-model="selectedChart" @change="updateChart" class="w-full p-2 border rounded mb-4">
        <option v-for="chartName in chartNames" :key="chartName" :value="chartName">
          {{ chartName }}
        </option>
      </select>

      <!-- Node Information Display -->
      <div v-if="selectedNodeInfo" class="mt-4 bg-white p-4 rounded shadow space-y-4">
        <!-- Header -->
        <div class="border-b pb-3">
          <h3 class="font-bold text-xl mb-2">{{ selectedNodeName }}</h3>
          <p class="text-lg text-gray-700">{{ selectedNodeInfo.name }}</p>
          
          <!-- Badges -->
          <div class="flex flex-wrap gap-2 mt-2">
            <span class="px-2 py-1 bg-blue-100 text-blue-800 text-xs rounded-full">
              {{ selectedNodeInfo.abstraction }}
            </span>
            <span v-if="selectedNodeInfo.status" class="px-2 py-1 bg-gray-100 text-gray-800 text-xs rounded-full">
              {{ selectedNodeInfo.status }}
            </span>
            <span v-if="selectedNodeInfo.cve_count > 0" class="px-2 py-1 bg-red-100 text-red-800 text-xs rounded-full font-semibold">
              {{ selectedNodeInfo.cve_count }} CVEs
            </span>
            <span v-if="selectedNodeInfo.likelihood_of_exploit !== 'Unknown'" 
                  class="px-2 py-1 bg-orange-100 text-orange-800 text-xs rounded-full">
              Exploit: {{ selectedNodeInfo.likelihood_of_exploit }}
            </span>
          </div>
        </div>

        <!-- Official Link -->
        <div>
          <a 
            :href="selectedNodeInfo.link"
            target="_blank"
            rel="noopener noreferrer"
            class="text-blue-600 hover:text-blue-800 hover:underline transition duration-300 ease-in-out inline-flex items-center font-semibold"
          >
            <span>View Official CWE Documentation</span>
            <svg class="w-4 h-4 ml-1" fill="currentColor" viewBox="0 0 20 20">
              <path d="M11 3a1 1 0 100 2h2.586l-6.293 6.293a1 1 0 101.414 1.414L15 6.414V9a1 1 0 102 0V4a1 1 0 00-1-1h-5z"></path>
              <path d="M5 5a2 2 0 00-2 2v8a2 2 0 002 2h8a2 2 0 002-2v-3a1 1 0 10-2 0v3H5V7h3a1 1 0 000-2H5z"></path>
            </svg>
          </a>
        </div>

        <!-- Description -->
        <section>
          <h4 class="font-bold text-md mb-2 text-gray-800">Description</h4>
          <p class="text-sm text-gray-700">{{ selectedNodeInfo.description }}</p>
          <p v-if="selectedNodeInfo.extended_description" class="text-sm text-gray-600 mt-2 italic">
            {{ selectedNodeInfo.extended_description }}
          </p>
        </section>

        <!-- Vulnerability Mapping -->
        <section>
          <h4 class="font-bold text-md mb-2 text-gray-800"> Vulnerability Mapping</h4>
          <span :class="getMappingClass(selectedNodeInfo.vulnerability_mapping)" 
                class="px-3 py-1 rounded-full text-sm font-semibold">
            {{ selectedNodeInfo.vulnerability_mapping }}
          </span>
        </section>

        <!-- Observed Examples (CVEs) -->
        <section v-if="selectedNodeInfo.observed_examples && selectedNodeInfo.observed_examples.length > 0">
          <h4 class="font-bold text-md mb-2 text-gray-800"> Real-World Examples (CVEs)</h4>
          <div class="space-y-2 max-h-60 overflow-y-auto">
            <div v-for="(example, index) in selectedNodeInfo.observed_examples" :key="index" 
                 class="bg-red-50 p-2 rounded text-sm border-l-4 border-red-400">
              <a :href="example.link" target="_blank" class="font-semibold text-red-700 hover:underline">
                {{ example.reference }}
              </a>
              <p class="text-gray-700 mt-1">{{ example.description }}</p>
            </div>
          </div>
        </section>

        <!-- Common Consequences -->
        <section v-if="selectedNodeInfo.consequences && selectedNodeInfo.consequences.length > 0">
          <h4 class="font-bold text-md mb-2 text-gray-800"> Common Consequences</h4>
          <div class="space-y-2">
            <div v-for="(consequence, index) in selectedNodeInfo.consequences" :key="index" 
                 class="bg-yellow-50 p-2 rounded text-sm">
              <p class="font-semibold text-yellow-800">
                Scope: {{ Array.isArray(consequence.scope) ? consequence.scope.join(', ') : consequence.scope }}
              </p>
              <p class="text-gray-700">
                Impact: {{ Array.isArray(consequence.impact) ? consequence.impact.join(', ') : consequence.impact }}
              </p>
              <p v-if="consequence.note" class="text-gray-600 mt-1 text-xs">{{ consequence.note }}</p>
            </div>
          </div>
        </section>

        <!-- Potential Mitigations -->
        <section v-if="selectedNodeInfo.mitigations && selectedNodeInfo.mitigations.length > 0">
          <h4 class="font-bold text-md mb-2 text-gray-800"> Mitigations</h4>
          <div class="space-y-2 max-h-60 overflow-y-auto">
            <div v-for="(mitigation, index) in selectedNodeInfo.mitigations" :key="index" 
                 class="bg-green-50 p-2 rounded text-sm border-l-4 border-green-400">
              <p class="font-semibold text-green-800">Phase: {{ mitigation.phase }}</p>
              <p class="text-gray-700 mt-1">{{ mitigation.description }}</p>
              <span v-if="mitigation.effectiveness" 
                    class="inline-block mt-1 px-2 py-0.5 bg-green-200 text-green-800 text-xs rounded">
                Effectiveness: {{ mitigation.effectiveness }}
              </span>
            </div>
          </div>
        </section>

        <!-- Detection Methods -->
        <section v-if="selectedNodeInfo.detection_methods && selectedNodeInfo.detection_methods.length > 0">
          <h4 class="font-bold text-md mb-2 text-gray-800"> Detection Methods</h4>
          <div class="space-y-2">
            <div v-for="(method, index) in selectedNodeInfo.detection_methods" :key="index" 
                 class="bg-purple-50 p-2 rounded text-sm">
              <p class="font-semibold text-purple-800">{{ method.method }}</p>
              <p class="text-gray-700 text-xs mt-1">{{ method.description }}</p>
              <span v-if="method.effectiveness" 
                    class="inline-block mt-1 px-2 py-0.5 bg-purple-200 text-purple-800 text-xs rounded">
                {{ method.effectiveness }}
              </span>
            </div>
          </div>
        </section>

        <!-- Applicable Platforms -->
        <section v-if="hasApplicablePlatforms(selectedNodeInfo.applicable_platforms)">
          <h4 class="font-bold text-md mb-2 text-gray-800"> Applicable Platforms</h4>
          <div class="space-y-2 text-sm">
            <div v-if="selectedNodeInfo.applicable_platforms.languages.length > 0">
              <p class="font-semibold text-gray-700">Languages:</p>
              <div class="flex flex-wrap gap-1 mt-1">
                <span v-for="(lang, index) in selectedNodeInfo.applicable_platforms.languages" :key="index"
                      class="px-2 py-1 bg-indigo-100 text-indigo-800 text-xs rounded">
                  {{ lang.name }}
                </span>
              </div>
            </div>
            <div v-if="selectedNodeInfo.applicable_platforms.technologies.length > 0">
              <p class="font-semibold text-gray-700">Technologies:</p>
              <div class="flex flex-wrap gap-1 mt-1">
                <span v-for="(tech, index) in selectedNodeInfo.applicable_platforms.technologies" :key="index"
                      class="px-2 py-1 bg-cyan-100 text-cyan-800 text-xs rounded">
                  {{ tech.name }}
                </span>
              </div>
            </div>
          </div>
        </section>

        <!-- Modes of Introduction -->
        <section v-if="selectedNodeInfo.modes_of_introduction && selectedNodeInfo.modes_of_introduction.length > 0">
          <h4 class="font-bold text-md mb-2 text-gray-800">Modes of Introduction</h4>
          <div class="space-y-1">
            <div v-for="(mode, index) in selectedNodeInfo.modes_of_introduction" :key="index" 
                 class="text-sm bg-gray-50 p-2 rounded">
              <span class="font-semibold">{{ mode.phase }}</span>
              <span v-if="mode.note" class="text-gray-600 ml-2">- {{ mode.note }}</span>
            </div>
          </div>
        </section>

        <!-- Attack Patterns (CAPEC) -->
        <section v-if="selectedNodeInfo.attack_patterns && selectedNodeInfo.attack_patterns.length > 0">
          <h4 class="font-bold text-md mb-2 text-gray-800"> Related Attack Patterns</h4>
          <div class="flex flex-wrap gap-2">
            <a v-for="(pattern, index) in selectedNodeInfo.attack_patterns" :key="index"
               :href="`https://capec.mitre.org/data/definitions/${pattern}.html`"
               target="_blank"
               class="px-2 py-1 bg-red-100 text-red-800 text-xs rounded hover:bg-red-200 transition">
              CAPEC-{{ pattern }}
            </a>
          </div>
        </section>

        <!-- Related Weaknesses -->
        <section v-if="selectedNodeInfo.related_weaknesses && selectedNodeInfo.related_weaknesses.length > 0">
          <h4 class="font-bold text-md mb-2 text-gray-800">Related Weaknesses</h4>
          <div class="space-y-1 max-h-40 overflow-y-auto">
            <div v-for="(weakness, index) in selectedNodeInfo.related_weaknesses" :key="index" 
                 class="text-sm bg-gray-50 p-2 rounded">
              <span class="font-semibold">{{ weakness.Nature }}</span>: 
              <span class="text-blue-600 ml-1">CWE-{{ weakness.CWE_ID }}</span>
              <span v-if="weakness.View_ID" class="text-gray-500 text-xs ml-2">
                (View: {{ weakness.View_ID }})
              </span>
            </div>
          </div>
        </section>

        <!-- Demonstrative Examples -->
        <section v-if="selectedNodeInfo.demonstrative_examples && selectedNodeInfo.demonstrative_examples.length > 0">
          <h4 class="font-bold text-md mb-2 text-gray-800">Code Examples</h4>
          <div class="text-sm text-gray-600">
            {{ selectedNodeInfo.demonstrative_examples.length }} example(s) available in official documentation
          </div>
        </section>

        <!-- Alternate Terms -->
        <section v-if="selectedNodeInfo.alternate_terms && selectedNodeInfo.alternate_terms.length > 0">
          <h4 class="font-bold text-md mb-2 text-gray-800">Alternate Terms</h4>
          <div class="space-y-1">
            <div v-for="(term, index) in selectedNodeInfo.alternate_terms" :key="index" 
                 class="text-sm">
              <span class="font-semibold">{{ term.term }}</span>
              <p v-if="term.description" class="text-gray-600 text-xs">{{ term.description }}</p>
            </div>
          </div>
        </section>

      </div>
      
      <div v-else class="mt-4 text-gray-500 italic">
         Click on a node in the graph to view detailed CWE information
      </div>
    </div>

    <!-- Right Side - Graph Visualization -->
    <div class="flex-1">
      <div ref="chartContainer" class="w-full h-full"></div>
    </div>
  </div>
</template>

<style scoped>
.overflow-y-auto {
  scrollbar-width: thin;
  scrollbar-color: #cbd5e0 #edf2f7;
}

.overflow-y-auto::-webkit-scrollbar {
  width: 8px;
}

.overflow-y-auto::-webkit-scrollbar-track {
  background: #edf2f7;
}

.overflow-y-auto::-webkit-scrollbar-thumb {
  background-color: #cbd5e0;
  border-radius: 4px;
  border: 2px solid #edf2f7;
}

/* Smooth scrolling for sections */
section {
  scroll-margin-top: 1rem;
}
</style>

<script>
import { onMounted, ref, watch } from 'vue'
import * as echarts from 'echarts'

export default {
  name: 'ChartPage',

  setup() {
    const chartContainer = ref(null)
    const chart = ref(null)
    const chartData = ref({})
    const selectedChart = ref('')
    const chartNames = ref([])
    const selectedNodeInfo = ref(null)
    const selectedNodeName = ref('')
    const nodeMetadata = ref({})

    // Load chart and metadata
    const loadChartData = async () => {
      try {
        const response1 = await fetch('/cwe-navigation/graph_data.json')
        chartData.value = await response1.json()
        chartNames.value = Object.keys(chartData.value)
        selectedChart.value = chartNames.value[2]

        const response2 = await fetch('/cwe-navigation/cwe_metadata.json')
        nodeMetadata.value = await response2.json()

        console.log('Chart data loaded successfully.')
        console.log('Sample metadata:', nodeMetadata.value['CWE-79']) // Debug
      } catch (error) {
        console.error('Load data failed:', error)
      }
    }

    // Initialize ECharts
    const initChart = () => {
      if (chartContainer.value) {
        chart.value = echarts.init(chartContainer.value, null, { renderer: 'svg' })
        chart.value.on('click', handleChartClick)
      }
    }

    // Handle node click
    const handleChartClick = (params) => {
      if (params.componentType === 'series' && params.seriesType === 'graph') {
        if (params.dataType === 'node') {
          console.log('Clicked:', params.data.name)
          selectedNodeName.value = params.data.name
          selectedNodeInfo.value = nodeMetadata.value[params.data.name]
          
          if (selectedNodeInfo.value) {
            selectedNodeInfo.value.link =
              'https://cwe.mitre.org/data/definitions/' + params.data.name.substring(4) + '.html'
          }
        } else {
          selectedNodeInfo.value = null
        }
      }
    }

    // Update chart visualization
    const updateChart = () => {
      if (chart.value && selectedChart.value) {
        const option = generateChartOption(chartData.value[selectedChart.value])
        chart.value.setOption(option)
      }
    }

    // Generate ECharts option
    const generateChartOption = (graph_data) => {
      return {
        legend: {
          data: graph_data.abstractions
        },
        tooltip: {},
        series: [
          {
            type: 'graph',
            layout: 'force',
            animation: false,
            roam: true,
            draggable: true,
            label: {
              position: 'right',
              formatter: '{b}'
            },
            data: graph_data.nodes,
            categories: graph_data.categories,
            force: {
              edgeLength: 10,
              repulsion: 10,
              gravity: 0.02
            },
            edges: graph_data.links,
            emphasis: {
              focus: 'adjacency',
              lineStyle: {
                opacity: 1,
                width: 2
              },
              itemStyle: {
                borderColor: '#aa0000',
                borderWidth: 2
              }
            }
          }
        ]
      }
    }

    // Helper function to get vulnerability mapping class
    const getMappingClass = (mapping) => {
      const classes = {
        'Allowed': 'bg-green-100 text-green-800',
        'Allowed-with-Review': 'bg-yellow-100 text-yellow-800',
        'Discouraged': 'bg-orange-100 text-orange-800',
        'Prohibited': 'bg-red-100 text-red-800'
      }
      return classes[mapping] || 'bg-gray-100 text-gray-800'
    }

    // Helper to check if there are any applicable platforms
    const hasApplicablePlatforms = (platforms) => {
      if (!platforms) return false
      return platforms.languages.length > 0 || 
             platforms.technologies.length > 0 || 
             platforms.architectures.length > 0 || 
             platforms.operating_systems.length > 0
    }

    onMounted(async () => {
      await loadChartData()
      initChart()
      updateChart()
    })

    watch(selectedChart, updateChart)

    return {
      chartContainer,
      selectedChart,
      chartNames,
      updateChart,
      selectedNodeName,
      selectedNodeInfo,
      getMappingClass,
      hasApplicablePlatforms
    }
  }
}
</script>