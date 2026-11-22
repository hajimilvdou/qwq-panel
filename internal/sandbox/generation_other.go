// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package sandbox

import "context"

func pinGenerationPlatform(context.Context, string, *ProcessProof, GenerationKernelPaths, GenerationProfileReader) (PinnedGeneration, error) {
	return nil, ErrGenerationUnsupported
}

func armGenerationStopPlatform(context.Context, string, PinnedGeneration, GenerationProfileReader) error {
	return ErrGenerationUnsupported
}
