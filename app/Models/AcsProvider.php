<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class AcsProvider extends Model
{
    use HasFactory;

    protected $fillable = [
        'user_id',
        'acs_url',
        'login_status'
    ];

    public function user()
    {
        return $this->belongsTo(User::class, 'user_id');
    }
}
