"""Standalone CLI, validated configuration and HIO/store lifetime composition.

This package starts feature tasks and OOBI resolution, and stops children before
closing their borrowed stores. Feature policy remains in its owning package.
"""
