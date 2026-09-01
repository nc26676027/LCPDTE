param(
    [Parameter(Mandatory = $true)]
    [string]$ModelDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-InternalNode {
    param(
        [object[]]$LeftChildren,
        [int]$Node
    )

    return $Node -ge 0 -and $Node -lt $LeftChildren.Count -and [int]$LeftChildren[$Node] -ge 0
}

function Get-MaxSameFeatureRun {
    param(
        [object[]]$LeftChildren,
        [object[]]$RightChildren,
        [object[]]$SplitIndices,
        [int]$Node,
        [int]$Feature
    )

    if (-not (Test-InternalNode $LeftChildren $Node) -or [int]$SplitIndices[$Node] -ne $Feature) {
        return 0
    }

    $leftRun = Get-MaxSameFeatureRun $LeftChildren $RightChildren $SplitIndices ([int]$LeftChildren[$Node]) $Feature
    $rightRun = Get-MaxSameFeatureRun $LeftChildren $RightChildren $SplitIndices ([int]$RightChildren[$Node]) $Feature
    return 1 + [Math]::Max($leftRun, $rightRun)
}

function Test-FullUniformSubtree {
    param(
        [object[]]$LeftChildren,
        [object[]]$RightChildren,
        [object[]]$SplitIndices,
        [int]$Node,
        [int]$Feature,
        [int]$Height
    )

    if ($Height -eq 0) {
        return $true
    }
    if (-not (Test-InternalNode $LeftChildren $Node) -or [int]$SplitIndices[$Node] -ne $Feature) {
        return $false
    }

    return (Test-FullUniformSubtree $LeftChildren $RightChildren $SplitIndices ([int]$LeftChildren[$Node]) $Feature ($Height - 1)) -and
        (Test-FullUniformSubtree $LeftChildren $RightChildren $SplitIndices ([int]$RightChildren[$Node]) $Feature ($Height - 1))
}

function Assert-TreeShape {
    param(
        [object]$Tree,
        [string]$ModelName,
        [int]$TreeIndex
    )

    $count = $Tree.left_children.Count
    foreach ($field in @("right_children", "split_indices", "split_conditions", "parents")) {
        if ($Tree.$field.Count -ne $count) {
            throw "$ModelName tree $TreeIndex has $field length $($Tree.$field.Count), want $count"
        }
    }
    for ($node = 0; $node -lt $count; $node++) {
        $left = [int]$Tree.left_children[$node]
        $right = [int]$Tree.right_children[$node]
        if (($left -lt 0) -ne ($right -lt 0)) {
            throw "$ModelName tree $TreeIndex node $node has only one child"
        }
        foreach ($child in @($left, $right)) {
            if ($child -ge $count) {
                throw "$ModelName tree $TreeIndex node $node has out-of-range child $child"
            }
        }
    }
}

$resolvedDirectory = (Resolve-Path -LiteralPath $ModelDirectory).Path
$modelFiles = @(Get-ChildItem -LiteralPath $resolvedDirectory -Filter "xgb_model_d*.json" -File | Sort-Object Name)
if ($modelFiles.Count -eq 0) {
    throw "no xgb_model_d*.json files found in $resolvedDirectory"
}

$reports = @()
foreach ($modelFile in $modelFiles) {
    $document = Get-Content -Raw -LiteralPath $modelFile.FullName | ConvertFrom-Json
    $trees = @($document.learner.gradient_booster.model.trees)
    $report = [ordered]@{
        model = $modelFile.Name
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $modelFile.FullName).Hash.ToLowerInvariant()
        tree_count = $trees.Count
        internal_nodes = 0
        internal_internal_edges = 0
        same_feature_internal_edges = 0
        same_feature_edge_fraction = 0.0
        same_feature_components = 0
        multi_node_components = 0
        nodes_in_multi_node_components = 0
        max_same_feature_path_run = 0
        full_uniform_height2_roots = 0
        full_uniform_height3_roots = 0
        full_uniform_height4_roots = 0
        candidate_edges = @()
    }

    for ($treeIndex = 0; $treeIndex -lt $trees.Count; $treeIndex++) {
        $tree = $trees[$treeIndex]
        Assert-TreeShape $tree $modelFile.Name $treeIndex
        $leftChildren = @($tree.left_children)
        $rightChildren = @($tree.right_children)
        $splitIndices = @($tree.split_indices)
        $splitConditions = @($tree.split_conditions)
        $parents = @($tree.parents)

        for ($node = 0; $node -lt $leftChildren.Count; $node++) {
            if (-not (Test-InternalNode $leftChildren $node)) {
                continue
            }
            $report.internal_nodes++
            $feature = [int]$splitIndices[$node]
            $run = Get-MaxSameFeatureRun $leftChildren $rightChildren $splitIndices $node $feature
            $report.max_same_feature_path_run = [Math]::Max($report.max_same_feature_path_run, $run)

            if (Test-FullUniformSubtree $leftChildren $rightChildren $splitIndices $node $feature 2) {
                $report.full_uniform_height2_roots++
            }
            if (Test-FullUniformSubtree $leftChildren $rightChildren $splitIndices $node $feature 3) {
                $report.full_uniform_height3_roots++
            }
            if (Test-FullUniformSubtree $leftChildren $rightChildren $splitIndices $node $feature 4) {
                $report.full_uniform_height4_roots++
            }

            foreach ($edge in @(
                [pscustomobject]@{ side = "left"; child = [int]$leftChildren[$node] },
                [pscustomobject]@{ side = "right"; child = [int]$rightChildren[$node] }
            )) {
                if (-not (Test-InternalNode $leftChildren $edge.child)) {
                    continue
                }
                $report.internal_internal_edges++
                if ([int]$splitIndices[$edge.child] -eq $feature) {
                    $report.same_feature_internal_edges++
                    $report.candidate_edges += [ordered]@{
                        tree_index = $treeIndex
                        parent_node = $node
                        child_node = $edge.child
                        side = $edge.side
                        feature = $feature
                        parent_threshold = [double]$splitConditions[$node]
                        child_threshold = [double]$splitConditions[$edge.child]
                    }
                }
            }

            $parent = [int64]$parents[$node]
            $isRoot = $parent -lt 0 -or $parent -eq [uint32]::MaxValue
            $startsComponent = $isRoot -or -not (Test-InternalNode $leftChildren ([int]$parent)) -or [int]$splitIndices[[int]$parent] -ne $feature
            if (-not $startsComponent) {
                continue
            }

            $report.same_feature_components++
            $stack = [System.Collections.Generic.Stack[int]]::new()
            $stack.Push($node)
            $componentSize = 0
            while ($stack.Count -gt 0) {
                $member = $stack.Pop()
                $componentSize++
                foreach ($child in @([int]$leftChildren[$member], [int]$rightChildren[$member])) {
                    if ((Test-InternalNode $leftChildren $child) -and [int]$splitIndices[$child] -eq $feature) {
                        $stack.Push($child)
                    }
                }
            }
            if ($componentSize -gt 1) {
                $report.multi_node_components++
                $report.nodes_in_multi_node_components += $componentSize
            }
        }
    }

    if ($report.internal_internal_edges -gt 0) {
        $report.same_feature_edge_fraction = $report.same_feature_internal_edges / $report.internal_internal_edges
    }
    $reports += [pscustomobject]$report
}

[pscustomobject]@{
    schema = "lcpdte.r0_same_feature_scan.v1"
    interpretation = "A full-uniform height-2 root requires the root and both internal children to split on the same feature. Candidate edges are necessary but not sufficient for an exact R0 fusion proof."
    models = $reports
} | ConvertTo-Json -Depth 8
