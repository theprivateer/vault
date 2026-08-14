<?php

use Illuminate\Support\Facades\Route;
use Inertia\Inertia;

Route::get('/', fn () => Inertia::render('Welcome', [
    'phase' => 'Phase 0 — foundations & guardrails',
]))->name('home');
